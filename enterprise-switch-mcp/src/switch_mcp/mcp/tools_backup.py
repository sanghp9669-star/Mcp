"""MCP Backup & Configuration Comparison Tools (4 tools)."""

import difflib
import hashlib
from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.core.exceptions import ValidationError
from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.security.rbac import RBACEnforcer, RiskLevel
from switch_mcp.services.network_service import NetworkService


def register_backup_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def backup_running_config(hostname: str) -> dict[str, Any]:
        """Snapshot live running-config to PostgreSQL with SHA-256 integrity hash."""
        ctx = get_ctx()
        async def _act(adapter: SwitchAdapter | None):
            device = await svc.repo.get_device_by_hostname(hostname)
            cfg = await adapter.backup_config("running")
            digest = hashlib.sha256(cfg.encode("utf-8")).hexdigest()
            bkp_id = await svc.repo.save_backup(str(device.id), "running", cfg, digest, ctx.username)
            return f"Backed up running-config ({len(cfg.splitlines())} lines).", {"backup_id": bkp_id, "sha256": digest}, []

        return await svc.execute_read_tool(ctx, "backup_running_config", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def backup_startup_config(hostname: str) -> dict[str, Any]:
        """Snapshot startup-config to PostgreSQL with SHA-256 integrity hash."""
        ctx = get_ctx()
        async def _act(adapter: SwitchAdapter | None):
            device = await svc.repo.get_device_by_hostname(hostname)
            cfg = await adapter.backup_config("startup")
            digest = hashlib.sha256(cfg.encode("utf-8")).hexdigest()
            bkp_id = await svc.repo.save_backup(str(device.id), "startup", cfg, digest, ctx.username)
            return f"Backed up startup-config ({len(cfg.splitlines())} lines).", {"backup_id": bkp_id, "sha256": digest}, []

        return await svc.execute_read_tool(ctx, "backup_startup_config", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def restore_config(
        hostname: str,
        config_text: str,
        approval_id: str | None = None,
        change_ticket: str | None = None,
    ) -> dict[str, Any]:
        """Restore switch configuration (CRITICAL risk: requires SuperAdmin + MFA + Change Ticket)."""
        ctx = get_ctx()
        RBACEnforcer.check_permission(ctx, "restore_config")
        AISafeGuardrails.inspect_commands("restore_config", config_text)
        device = await svc.repo.get_device_by_hostname(hostname)
        lines = [ln for ln in config_text.splitlines() if ln.strip() and not ln.strip().startswith("!")]

        if not approval_id:
            cr = await svc.approval.create_change_request(
                ctx=ctx,
                device_id=str(device.id),
                tool_name="restore_config",
                parameters={"hostname": hostname, "line_count": len(lines)},
                cli_commands=lines[:50],
                risk=RiskLevel.CRITICAL,
                change_ticket=change_ticket,
            )
            audit_id = await svc.audit.record_event(
                ctx=ctx,
                tool_name="restore_config",
                parameters={"hostname": hostname, "line_count": len(lines)},
                device_hostname=hostname,
                result_status="pending_approval",
                result_summary=f"CRITICAL restore requires SuperAdmin + MFA + Ticket ({cr['request_code']}).",
                risk_level="CRITICAL",
                approval_id=cr["request_code"],
            )
            return {
                "status": "pending_approval",
                "hostname": hostname,
                "summary": f"CRITICAL restore paused pending SuperAdmin + MFA + Change Ticket ({cr['request_code']}).",
                "risk": "CRITICAL",
                "recommendations": [
                    f"SuperAdmin must approve via approve_change('{cr['request_code']}', mfa_code='...', change_ticket='CHG-...')",
                ],
                "audit_id": audit_id,
                "change_request": cr,
            }

        await svc.approval.verify_approved_execution(approval_id, "restore_config")
        async with svc.redis.device_lock(hostname):
            adapter = await svc.open_adapter(hostname)
            async with adapter:
                res = await adapter.restore_config(config_text, replace=False)

        await svc.approval.mark_executed(approval_id)
        audit_id = await svc.audit.record_event(
            ctx=ctx,
            tool_name="restore_config",
            parameters={"hostname": hostname, "line_count": len(lines)},
            device_hostname=hostname,
            result_status="success",
            result_summary="Configuration restored after SuperAdmin MFA & Change Ticket verification.",
            risk_level="CRITICAL",
            approval_id=approval_id,
        )
        return {
            "status": "success",
            "hostname": hostname,
            "summary": f"Restored {res['applied_lines']} config lines on {hostname}.",
            "risk": "CRITICAL",
            "recommendations": ["Verify running-config vs startup-config parity."],
            "audit_id": audit_id,
            "approval_id": approval_id,
            "data": res,
        }

    @mcp.tool()
    async def compare_configs(hostname: str) -> dict[str, Any]:
        """Compute unified diff between live running-config and saved startup-config."""
        async def _act(adapter: SwitchAdapter | None):
            running = (await adapter.backup_config("running")).splitlines()
            startup = (await adapter.backup_config("startup")).splitlines()
            diff = list(difflib.unified_diff(startup, running, fromfile="startup-config", tofile="running-config", lineterm=""))
            recs = ["Unsaved running-config drift detected; consider saving configuration."] if diff else []
            return f"Computed config diff ({len(diff)} diff lines).", {"has_drift": bool(diff), "diff": diff[:200]}, recs

        return await svc.execute_read_tool(get_ctx(), "compare_configs", hostname, {"hostname": hostname}, _act)
