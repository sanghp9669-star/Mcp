"""MCP Change Management & Approval Workflow Tools (4 tools)."""

from typing import Any

from fastmcp import FastMCP

from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.security.rbac import RBACEnforcer, RiskLevel
from switch_mcp.services.network_service import NetworkService


def register_approval_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def create_change_request(
        hostname: str,
        tool_name: str,
        cli_commands: list[str],
        risk_level: str = "MEDIUM",
        change_ticket: str | None = None,
    ) -> dict[str, Any]:
        """Generate an auditable Change Plan and submit a Change Request for approval."""
        ctx = get_ctx()
        RBACEnforcer.check_permission(ctx, "create_change_request")
        device = await svc.repo.get_device_by_hostname(hostname)
        risk = RiskLevel(risk_level.upper())

        # Note: destructive commands are allowed inside a Change Request plan for manual CAB review,
        # never executed via MCP.
        cr = await svc.approval.create_change_request(
            ctx=ctx,
            device_id=str(device.id),
            tool_name=tool_name,
            parameters={"hostname": hostname, "requested_cli": cli_commands},
            cli_commands=cli_commands,
            risk=risk,
            change_ticket=change_ticket,
        )
        audit_id = await svc.audit.record_event(
            ctx=ctx,
            tool_name="create_change_request",
            parameters={"hostname": hostname, "target_tool": tool_name, "risk": risk.value},
            device_hostname=hostname,
            result_status="success",
            result_summary=f"Created change request {cr['request_code']} ({risk.value}).",
            risk_level=risk.value,
            approval_id=cr["request_code"],
        )
        return {
            "status": "success",
            "hostname": hostname,
            "summary": f"Change Request {cr['request_code']} created for '{tool_name}' ({risk.value} risk).",
            "risk": risk.value,
            "recommendations": ["Obtain required approvals before execution."],
            "audit_id": audit_id,
            "data": cr,
        }

    @mcp.tool()
    async def approve_change(
        request_code: str,
        mfa_code: str | None = None,
        change_ticket: str | None = None,
        comment: str = "Approved via MCP",
    ) -> dict[str, Any]:
        """Approve a pending Change Request (enforces 4-eyes, SuperAdmin, MFA, and Ticket rules)."""
        ctx = get_ctx()
        RBACEnforcer.check_permission(ctx, "approve_change")
        res = await svc.approval.approve_change(
            ctx=ctx,
            request_code=request_code,
            mfa_code=mfa_code,
            change_ticket=change_ticket,
            comment=comment,
        )
        audit_id = await svc.audit.record_event(
            ctx=ctx,
            tool_name="approve_change",
            parameters={"request_code": request_code, "change_ticket": change_ticket},
            device_hostname="GLOBAL",
            result_status="success",
            result_summary=f"Recorded approval on {request_code}: status={res['status']}.",
            risk_level="LOW",
            approval_id=request_code,
        )
        return {
            "status": "success",
            "hostname": "GLOBAL",
            "summary": f"Change {request_code} status is now {res['status']} ({res['approved_count']}/{res['required_approvals']}).",
            "risk": "LOW",
            "recommendations": [],
            "audit_id": audit_id,
            "data": res,
        }

    @mcp.tool()
    async def reject_change(request_code: str, reason: str) -> dict[str, Any]:
        """Reject a pending Change Request with a mandatory audit reason."""
        ctx = get_ctx()
        RBACEnforcer.check_permission(ctx, "reject_change")
        res = await svc.approval.reject_change(ctx, request_code, reason)
        audit_id = await svc.audit.record_event(
            ctx=ctx,
            tool_name="reject_change",
            parameters={"request_code": request_code, "reason": reason},
            device_hostname="GLOBAL",
            result_status="success",
            result_summary=f"Rejected {request_code}: {reason}",
            risk_level="LOW",
            approval_id=request_code,
        )
        return {
            "status": "success",
            "hostname": "GLOBAL",
            "summary": f"Change Request {request_code} rejected.",
            "risk": "LOW",
            "recommendations": [],
            "audit_id": audit_id,
            "data": res,
        }

    @mcp.tool()
    async def view_pending_changes() -> dict[str, Any]:
        """List all pending Change Requests awaiting approval."""
        ctx = get_ctx()
        RBACEnforcer.check_permission(ctx, "view_pending_changes")
        pending = await svc.repo.list_pending_changes()
        audit_id = await svc.audit.record_event(
            ctx=ctx,
            tool_name="view_pending_changes",
            parameters={},
            device_hostname="GLOBAL",
            result_status="success",
            result_summary=f"Listed {len(pending)} pending change requests.",
            risk_level="LOW",
        )
        return {
            "status": "success",
            "hostname": "GLOBAL",
            "summary": f"Found {len(pending)} pending change requests.",
            "risk": "LOW",
            "recommendations": [],
            "audit_id": audit_id,
            "data": pending,
        }
