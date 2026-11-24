"""Immutable SHA-256 Hash-Chained Audit Engine."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from switch_mcp.core.logging import get_logger
from switch_mcp.db.models import AuditLogORM
from switch_mcp.db.repository import SwitchRepository
from switch_mcp.queue.rabbitmq import RabbitMQBus
from switch_mcp.security.auth import RequestContext

_log = get_logger(__name__)


class AuditEngine:
    """Appends tamper-evident hash-chained audit records to PostgreSQL and RabbitMQ."""

    def __init__(self, repo: SwitchRepository, bus: RabbitMQBus) -> None:
        self._repo = repo
        self._bus = bus

    async def record_event(
        self,
        ctx: RequestContext,
        tool_name: str,
        parameters: dict[str, Any],
        device_hostname: str | None,
        result_status: str,
        result_summary: str,
        risk_level: str,
        approval_id: str | None = None,
    ) -> str:
        prev_hash, latest_seq = await self._repo.get_latest_audit_hash()
        audit_id = f"AUD-{latest_seq + 1:06d}-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        sanitized_params = {
            k: ("***REDACTED***" if "secret" in k or "password" in k or "mfa" in k else v)
            for k, v in parameters.items()
        }

        canonical_payload = json.dumps(
            {
                "audit_id": audit_id,
                "timestamp": timestamp,
                "user_id": ctx.user_id,
                "username": ctx.username,
                "role": ctx.role,
                "ai_agent": ctx.ai_agent,
                "source_ip": ctx.source_ip,
                "tool": tool_name,
                "parameters": sanitized_params,
                "device": device_hostname,
                "status": result_status,
                "approval_id": approval_id,
                "risk": risk_level,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            default=str,
        )
        record_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

        entry = AuditLogORM(
            audit_id=audit_id,
            user_id=ctx.user_id,
            username=ctx.username,
            role_name=ctx.role,
            ai_agent=ctx.ai_agent,
            source_ip=ctx.source_ip,
            tool_name=tool_name,
            parameters=sanitized_params,
            device_hostname=device_hostname,
            result_status=result_status,
            result_summary=result_summary,
            approval_id=approval_id,
            risk_level=risk_level,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        await self._repo.append_audit_log(entry)

        await self._bus.publish_event(
            routing_key=f"audit.{risk_level.lower()}.{result_status.lower()}",
            payload={
                "audit_id": audit_id,
                "timestamp": timestamp,
                "username": ctx.username,
                "role": ctx.role,
                "ai_agent": ctx.ai_agent,
                "source_ip": ctx.source_ip,
                "tool": tool_name,
                "device": device_hostname,
                "status": result_status,
                "risk_level": risk_level,
                "approval_id": approval_id,
                "record_hash": record_hash,
            },
        )
        _log.info(
            "audit_recorded",
            audit_id=audit_id,
            tool=tool_name,
            device=device_hostname,
            status=result_status,
            risk=risk_level,
        )
        return audit_id
