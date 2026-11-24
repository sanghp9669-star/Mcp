"""Async SQLAlchemy ORM models mirroring the PostgreSQL schema."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DeviceORM(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    mgmt_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(64))
    serial_number: Mapped[str | None] = mapped_column(String(64))
    is_stacked: Mapped[bool] = mapped_column(Boolean, default=False)
    stack_count: Mapped[int] = mapped_column(Integer, default=1)
    vault_secret_path: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="online")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLogORM(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    role_name: Mapped[str] = mapped_column(String(32), nullable=False)
    ai_agent: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    device_hostname: Mapped[str | None] = mapped_column(String(128))
    result_status: Mapped[str] = mapped_column(String(24), nullable=False)
    result_summary: Mapped[str] = mapped_column(Text, nullable=False)
    approval_id: Mapped[str | None] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ChangeRequestORM(Base):
    __tablename__ = "change_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    ai_agent: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    change_plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cli_commands: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    requires_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    change_ticket: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class HealthReportORM(Base):
    __tablename__ = "health_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    cpu_5min_pct: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    memory_used_pct: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    temperature_celsius: Mapped[float | None] = mapped_column(Numeric(5, 2))
    stack_status: Mapped[str] = mapped_column(String(24), nullable=False)
    raw_metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
