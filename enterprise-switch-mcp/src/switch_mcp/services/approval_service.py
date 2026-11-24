"""Change Management & Multi-Tier Approval Workflow Engine."""

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from switch_mcp.core.exceptions import AuthorizationError, ValidationError
from switch_mcp.core.telemetry import APPROVAL_REQUESTS_TOTAL
from switch_mcp.db.repository import PostgresDatabase
from switch_mcp.security.auth import AuthService, RequestContext
from switch_mcp.security.rbac import RiskLevel, Role


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    required_approvals: int
    requires_superadmin: bool
    requires_mfa: bool
    requires_change_ticket: bool


RISK_POLICY_MAP: dict[RiskLevel, ApprovalPolicy] = {
    RiskLevel.LOW: ApprovalPolicy(0, False, False, False),
    RiskLevel.MEDIUM: ApprovalPolicy(1, False, False, False),
    RiskLevel.HIGH: ApprovalPolicy(2, False, False, False),
    RiskLevel.CRITICAL: ApprovalPolicy(1, True, True, True),
}


class ApprovalEngine:
    """Manages Change Requests, Risk Assessment, and Multi-Approver Sign-Off."""

    def __init__(self, db: PostgresDatabase) -> None:
        self._db = db

    @staticmethod
    def assess_policy(risk: RiskLevel) -> ApprovalPolicy:
        return RISK_POLICY_MAP[risk]

    async def create_change_request(
        self,
        ctx: RequestContext,
        device_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        cli_commands: list[str],
        risk: RiskLevel,
        change_ticket: str | None = None,
        rollback_plan: list[str] | None = None,
    ) -> dict[str, Any]:
        policy = self.assess_policy(risk)
        request_code = f"CR-{uuid.uuid4().hex[:8].upper()}"
        change_plan = {
            "tool": tool_name,
            "risk_level": risk.value,
            "policy": {
                "required_approvals": policy.required_approvals,
                "requires_superadmin": policy.requires_superadmin,
                "requires_mfa": policy.requires_mfa,
                "requires_change_ticket": policy.requires_change_ticket,
            },
            "pre_checks": ["backup_running_config", "verify_uplink_redundancy"],
            "execution_steps": cli_commands,
            "rollback_steps": rollback_plan or ["restore_config from pre-change snapshot"],
        }

        async with self._db.write_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO change_requests (
                        request_code, device_id, requested_by, ai_agent, tool_name,
                        parameters, change_plan, cli_commands, risk_level,
                        required_approvals, requires_mfa, change_ticket, status
                    ) VALUES (
                        :request_code, :device_id, :requested_by, :ai_agent, :tool_name,
                        CAST(:parameters AS jsonb), CAST(:change_plan AS jsonb), CAST(:cli_commands AS jsonb),
                        :risk_level, :required_approvals, :requires_mfa, :change_ticket, 'PENDING'
                    )
                    """
                ),
                {
                    "request_code": request_code,
                    "device_id": device_id,
                    "requested_by": ctx.user_id,
                    "ai_agent": ctx.ai_agent,
                    "tool_name": tool_name,
                    "parameters": __import__("json").dumps(parameters, default=str),
                    "change_plan": __import__("json").dumps(change_plan),
                    "cli_commands": __import__("json").dumps(cli_commands),
                    "risk_level": risk.value,
                    "required_approvals": policy.required_approvals,
                    "requires_mfa": policy.requires_mfa,
                    "change_ticket": change_ticket,
                },
            )

        APPROVAL_REQUESTS_TOTAL.labels(risk_level=risk.value, state="PENDING").inc()
        return {
            "request_code": request_code,
            "status": "PENDING",
            "risk_level": risk.value,
            "required_approvals": policy.required_approvals,
            "requires_superadmin": policy.requires_superadmin,
            "requires_mfa": policy.requires_mfa,
            "requires_change_ticket": policy.requires_change_ticket,
            "change_plan": change_plan,
        }

    async def approve_change(
        self,
        ctx: RequestContext,
        request_code: str,
        mfa_code: str | None = None,
        change_ticket: str | None = None,
        comment: str = "",
    ) -> dict[str, Any]:
        async with self._db.write_session() as session:
            res = await session.execute(
                text("SELECT * FROM change_requests WHERE request_code = :code FOR UPDATE"),
                {"code": request_code},
            )
            cr = res.mappings().first()
            if not cr:
                raise ValidationError(f"Change request '{request_code}' not found")
            if cr["status"] != "PENDING":
                raise ValidationError(f"Change request '{request_code}' is already {cr['status']}")
            if str(cr["requested_by"]) == ctx.user_id and cr["risk_level"] in ("HIGH", "CRITICAL"):
                raise AuthorizationError("Four-eyes principle: requester cannot self-approve HIGH/CRITICAL changes")

            risk = RiskLevel(cr["risk_level"])
            policy = self.assess_policy(risk)

            if policy.requires_superadmin and ctx.role != Role.SUPER_ADMIN.value:
                raise AuthorizationError("CRITICAL changes can only be approved by SuperAdmin")

            mfa_ok = ctx.mfa_verified
            if policy.requires_mfa:
                if ctx.mfa_secret and mfa_code:
                    mfa_ok = AuthService.verify_totp(ctx.mfa_secret, mfa_code)
                elif mfa_code and mfa_code.isdigit() and len(mfa_code) == 6 and ctx.mfa_verified:
                    mfa_ok = True
                if not mfa_ok:
                    raise AuthorizationError("CRITICAL change approval requires valid MFA TOTP verification")

            effective_ticket = change_ticket or cr["change_ticket"]
            if policy.requires_change_ticket and not effective_ticket:
                raise ValidationError("CRITICAL change approval requires an enterprise Change Ticket ID (e.g. CHG-2026-0001)")

            await session.execute(
                text(
                    """
                    INSERT INTO approvals (change_request_id, approver_id, decision, mfa_verified, comment)
                    VALUES (:cr_id, :approver_id, 'APPROVED', :mfa_verified, :comment)
                    """
                ),
                {
                    "cr_id": cr["id"],
                    "approver_id": ctx.user_id,
                    "mfa_verified": mfa_ok,
                    "comment": comment,
                },
            )

            cnt_res = await session.execute(
                text(
                    "SELECT COUNT(*) FROM approvals WHERE change_request_id = :cr_id AND decision = 'APPROVED'"
                ),
                {"cr_id": cr["id"]},
            )
            approved_count = int(cnt_res.scalar_one())

            new_status = "APPROVED" if approved_count >= int(cr["required_approvals"]) else "PENDING"
            await session.execute(
                text(
                    """
                    UPDATE change_requests
                    SET status = :status, change_ticket = COALESCE(:ticket, change_ticket), updated_at = NOW()
                    WHERE id = :cr_id
                    """
                ),
                {"status": new_status, "ticket": effective_ticket, "cr_id": cr["id"]},
            )

        APPROVAL_REQUESTS_TOTAL.labels(risk_level=risk.value, state=new_status).inc()
        return {
            "request_code": request_code,
            "status": new_status,
            "approved_count": approved_count,
            "required_approvals": int(cr["required_approvals"]),
            "change_ticket": effective_ticket,
        }

    async def reject_change(self, ctx: RequestContext, request_code: str, reason: str) -> dict[str, Any]:
        async with self._db.write_session() as session:
            res = await session.execute(
                text("SELECT id, risk_level FROM change_requests WHERE request_code = :code FOR UPDATE"),
                {"code": request_code},
            )
            cr = res.mappings().first()
            if not cr:
                raise ValidationError(f"Change request '{request_code}' not found")
            await session.execute(
                text(
                    """
                    INSERT INTO approvals (change_request_id, approver_id, decision, mfa_verified, comment)
                    VALUES (:cr_id, :approver_id, 'REJECTED', :mfa, :comment)
                    """
                ),
                {"cr_id": cr["id"], "approver_id": ctx.user_id, "mfa": ctx.mfa_verified, "comment": reason},
            )
            await session.execute(
                text("UPDATE change_requests SET status = 'REJECTED', updated_at = NOW() WHERE id = :cr_id"),
                {"cr_id": cr["id"]},
            )
        APPROVAL_REQUESTS_TOTAL.labels(risk_level=cr["risk_level"], state="REJECTED").inc()
        return {"request_code": request_code, "status": "REJECTED", "reason": reason}

    async def verify_approved_execution(self, approval_id: str, tool_name: str) -> dict[str, Any]:
        async with self._db.read_session() as session:
            res = await session.execute(
                text("SELECT * FROM change_requests WHERE request_code = :code"),
                {"code": approval_id},
            )
            cr = res.mappings().first()
            if not cr or cr["status"] != "APPROVED":
                raise AuthorizationError(f"Approval '{approval_id}' is not in APPROVED state")
            if cr["tool_name"] != tool_name:
                raise AuthorizationError(f"Approval '{approval_id}' is scoped to '{cr['tool_name']}', not '{tool_name}'")
            return dict(cr)

    async def mark_executed(self, approval_id: str) -> None:
        async with self._db.write_session() as session:
            await session.execute(
                text("UPDATE change_requests SET status = 'EXECUTED', updated_at = NOW() WHERE request_code = :code"),
                {"code": approval_id},
            )
