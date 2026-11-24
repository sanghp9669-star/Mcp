"""Async PostgreSQL connection pool and parameterized repositories."""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from switch_mcp.core.config import Settings
from switch_mcp.core.exceptions import DeviceNotFoundError
from switch_mcp.db.models import AuditLogORM, ChangeRequestORM, DeviceORM


class PostgresDatabase:
    """Manages Primary (read/write) and Replica (read-only) asyncpg engines."""

    def __init__(self, settings: Settings) -> None:
        self._write_engine: AsyncEngine = create_async_engine(
            settings.postgres_dsn.get_secret_value(),
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            pool_pre_ping=True,
        )
        read_dsn = (
            settings.postgres_read_dsn.get_secret_value()
            if settings.postgres_read_dsn
            else settings.postgres_dsn.get_secret_value()
        )
        self._read_engine: AsyncEngine = create_async_engine(
            read_dsn,
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            pool_pre_ping=True,
        )
        self._write_session = async_sessionmaker(self._write_engine, expire_on_commit=False)
        self._read_session = async_sessionmaker(self._read_engine, expire_on_commit=False)

    @asynccontextmanager
    async def write_session(self) -> AsyncIterator[AsyncSession]:
        async with self._write_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @asynccontextmanager
    async def read_session(self) -> AsyncIterator[AsyncSession]:
        async with self._read_session() as session:
            yield session

    async def health_check(self) -> bool:
        try:
            async with self.read_session() as session:
                await session.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def close(self) -> None:
        await self._write_engine.dispose()
        await self._read_engine.dispose()


class SwitchRepository:
    """Parameterized CRUD & queries for devices, backups, audit logs, and approvals."""

    def __init__(self, db: PostgresDatabase) -> None:
        self._db = db

    async def list_devices(self, vendor: str | None = None) -> list[dict[str, Any]]:
        async with self._db.read_session() as session:
            stmt = select(DeviceORM)
            if vendor:
                stmt = stmt.where(DeviceORM.vendor == vendor.lower())
            result = await session.execute(stmt.order_by(DeviceORM.hostname))
            return [
                {
                    "id": str(d.id),
                    "hostname": d.hostname,
                    "mgmt_ip": str(d.mgmt_ip),
                    "vendor": d.vendor,
                    "model": d.model,
                    "os_version": d.os_version,
                    "is_stacked": d.is_stacked,
                    "stack_count": d.stack_count,
                    "status": d.status,
                    "vault_secret_path": d.vault_secret_path,
                }
                for d in result.scalars().all()
            ]

    async def get_device_by_hostname(self, hostname: str) -> DeviceORM:
        async with self._db.read_session() as session:
            stmt = select(DeviceORM).where(DeviceORM.hostname == hostname)
            device = (await session.execute(stmt)).scalar_one_or_none()
            if not device:
                raise DeviceNotFoundError(f"Switch '{hostname}' not registered in inventory")
            return device

    async def ensure_site(
        self,
        site_code: str,
        name: str | None = None,
        region: str = "APAC",
    ) -> str:
        """Resolve an existing site UUID or create the site record atomically."""
        async with self._db.write_session() as session:
            existing = await session.execute(
                text("SELECT id FROM sites WHERE site_code = :code"),
                {"code": site_code},
            )
            row = existing.first()
            if row:
                return str(row[0])
            created = await session.execute(
                text(
                    """
                    INSERT INTO sites (site_code, name, region)
                    VALUES (:code, :name, :region)
                    RETURNING id
                    """
                ),
                {"code": site_code, "name": name or site_code, "region": region},
            )
            return str(created.scalar_one())

    async def add_device(
        self,
        *,
        site_id: str,
        hostname: str,
        mgmt_ip: str,
        ssh_port: int,
        vendor: str,
        model: str,
        os_version: str | None,
        serial_number: str | None,
        is_stacked: bool,
        stack_count: int,
        vault_secret_path: str,
        status: str = "online",
    ) -> dict[str, Any]:
        """Insert or update a switch device record in PostgreSQL."""
        async with self._db.write_session() as session:
            res = await session.execute(
                text(
                    """
                    INSERT INTO devices (
                        site_id, hostname, mgmt_ip, ssh_port, vendor, model,
                        os_version, serial_number, is_stacked, stack_count,
                        vault_secret_path, status, last_seen_at
                    ) VALUES (
                        :site_id, :hostname, CAST(:mgmt_ip AS inet), :ssh_port, :vendor, :model,
                        :os_version, :serial_number, :is_stacked, :stack_count,
                        :vault_secret_path, :status, NOW()
                    )
                    ON CONFLICT (hostname) DO UPDATE SET
                        mgmt_ip = EXCLUDED.mgmt_ip,
                        ssh_port = EXCLUDED.ssh_port,
                        vendor = EXCLUDED.vendor,
                        model = EXCLUDED.model,
                        os_version = COALESCE(EXCLUDED.os_version, devices.os_version),
                        serial_number = COALESCE(EXCLUDED.serial_number, devices.serial_number),
                        is_stacked = EXCLUDED.is_stacked,
                        stack_count = EXCLUDED.stack_count,
                        vault_secret_path = EXCLUDED.vault_secret_path,
                        status = EXCLUDED.status,
                        last_seen_at = NOW()
                    RETURNING id, hostname, mgmt_ip, ssh_port, vendor, model, os_version,
                              serial_number, is_stacked, stack_count, vault_secret_path, status
                    """
                ),
                {
                    "site_id": site_id,
                    "hostname": hostname,
                    "mgmt_ip": mgmt_ip,
                    "ssh_port": ssh_port,
                    "vendor": vendor,
                    "model": model,
                    "os_version": os_version,
                    "serial_number": serial_number,
                    "is_stacked": is_stacked,
                    "stack_count": stack_count,
                    "vault_secret_path": vault_secret_path,
                    "status": status,
                },
            )
            row = res.mappings().one()
            return {
                "id": str(row["id"]),
                "hostname": row["hostname"],
                "mgmt_ip": str(row["mgmt_ip"]),
                "ssh_port": row["ssh_port"],
                "vendor": row["vendor"],
                "model": row["model"],
                "os_version": row["os_version"],
                "serial_number": row["serial_number"],
                "is_stacked": row["is_stacked"],
                "stack_count": row["stack_count"],
                "vault_secret_path": row["vault_secret_path"],
                "status": row["status"],
            }

    async def remove_device(self, hostname: str) -> str:
        """Delete a device from inventory and return its Vault secret path."""
        async with self._db.write_session() as session:
            res = await session.execute(
                text("DELETE FROM devices WHERE hostname = :hostname RETURNING vault_secret_path"),
                {"hostname": hostname},
            )
            row = res.first()
            if not row:
                raise DeviceNotFoundError(f"Switch '{hostname}' not registered in inventory")
            return str(row[0])

    async def get_latest_audit_hash(self) -> tuple[str, int]:
        async with self._db.read_session() as session:
            res = await session.execute(
                text("SELECT record_hash, id FROM audit_logs ORDER BY id DESC LIMIT 1")
            )
            row = res.first()
            if row:
                return str(row[0]), int(row[1])
            return "0" * 64, 0

    async def append_audit_log(self, entry: AuditLogORM) -> None:
        async with self._db.write_session() as session:
            session.add(entry)

    async def query_audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self._db.read_session() as session:
            res = await session.execute(
                select(AuditLogORM).order_by(AuditLogORM.id.desc()).limit(limit)
            )
            return [
                {
                    "audit_id": r.audit_id,
                    "username": r.username,
                    "role": r.role_name,
                    "ai_agent": r.ai_agent,
                    "tool": r.tool_name,
                    "device": r.device_hostname,
                    "status": r.result_status,
                    "risk": r.risk_level,
                    "approval_id": r.approval_id,
                    "record_hash": r.record_hash,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in res.scalars().all()
            ]

    async def save_backup(
        self,
        device_id: str,
        config_type: str,
        config_text: str,
        sha256_hash: str,
        username: str,
    ) -> str:
        async with self._db.write_session() as session:
            cfg_res = await session.execute(
                text(
                    """
                    INSERT INTO configs (device_id, config_type, config_text, sha256_hash, collected_by)
                    VALUES (:device_id, :config_type, :config_text, :sha256_hash, :collected_by)
                    RETURNING id
                    """
                ),
                {
                    "device_id": device_id,
                    "config_type": config_type,
                    "config_text": config_text,
                    "sha256_hash": sha256_hash,
                    "collected_by": username,
                },
            )
            config_id = str(cfg_res.scalar_one())
            bkp_res = await session.execute(
                text(
                    """
                    INSERT INTO backups (device_id, config_id, backup_type, sha256_hash)
                    VALUES (:device_id, :config_id, :backup_type, :sha256_hash)
                    RETURNING id
                    """
                ),
                {
                    "device_id": device_id,
                    "config_id": config_id,
                    "backup_type": config_type,
                    "sha256_hash": sha256_hash,
                },
            )
            return str(bkp_res.scalar_one())

    async def list_pending_changes(self) -> list[dict[str, Any]]:
        async with self._db.read_session() as session:
            res = await session.execute(
                select(ChangeRequestORM)
                .where(ChangeRequestORM.status == "PENDING")
                .order_by(ChangeRequestORM.created_at.desc())
            )
            return [
                {
                    "request_code": cr.request_code,
                    "tool_name": cr.tool_name,
                    "risk_level": cr.risk_level,
                    "required_approvals": cr.required_approvals,
                    "requires_mfa": cr.requires_mfa,
                    "change_ticket": cr.change_ticket,
                    "status": cr.status,
                    "cli_commands": cr.cli_commands,
                }
                for cr in res.scalars().all()
            ]
