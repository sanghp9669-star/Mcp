"""Network Service Layer orchestrating Auth, RBAC, Guardrails, Approval, Locking, Adapters, and Audit."""

import time
from typing import Any, Awaitable, Callable

from switch_mcp.adapters.base import DeviceConnectionSpec, SwitchAdapter
from switch_mcp.adapters.factory import SwitchAdapterFactory
from switch_mcp.cache.redis_client import RedisLayer
from switch_mcp.core.config import Settings
from switch_mcp.core.exceptions import (
    ApprovalRequiredError,
    GuardrailViolationError,
    SwitchMCPError,
)
from switch_mcp.core.telemetry import MCP_TOOL_CALLS_TOTAL, MCP_TOOL_DURATION_SECONDS
from switch_mcp.db.repository import SwitchRepository
from switch_mcp.security.auth import RequestContext
from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.security.rbac import RBACEnforcer, RiskLevel
from switch_mcp.security.vault import SwitchCredentials, VaultClient
from switch_mcp.services.approval_service import ApprovalEngine
from switch_mcp.services.audit_service import AuditEngine


class NetworkService:
    """Central service layer invoked by all FastMCP tools and resources."""

    def __init__(
        self,
        settings: Settings,
        repo: SwitchRepository,
        redis: RedisLayer,
        vault: VaultClient,
        audit: AuditEngine,
        approval: ApprovalEngine,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self.redis = redis
        self.vault = vault
        self.audit = audit
        self.approval = approval

    async def open_adapter(self, hostname: str) -> SwitchAdapter:
        device = await self.repo.get_device_by_hostname(hostname)
        creds = await self.vault.get_switch_credentials(device.vault_secret_path)
        spec = DeviceConnectionSpec(
            device_id=str(device.id),
            hostname=device.hostname,
            mgmt_ip=str(device.mgmt_ip),
            port=device.ssh_port,
            vendor=device.vendor,
            model=device.model,
            is_stacked=device.is_stacked,
            stack_count=device.stack_count,
            username=creds.username,
            password=creds.password,
            enable_secret=creds.enable_secret,
            ssh_private_key=creds.ssh_private_key,
            connect_timeout=self.settings.ssh_connect_timeout,
            command_timeout=self.settings.ssh_command_timeout,
        )
        return SwitchAdapterFactory.create(spec)

    async def onboard_device(
        self,
        ctx: RequestContext,
        *,
        hostname: str,
        mgmt_ip: str,
        vendor: str,
        model: str,
        site_code: str,
        ssh_username: str,
        ssh_password: str,
        enable_secret: str | None = None,
        ssh_private_key: str | None = None,
        ssh_port: int = 22,
        is_stacked: bool = False,
        verify_ssh: bool = True,
    ) -> dict[str, Any]:
        """Validate, verify SSH connectivity, store credentials in Vault, and register switch in PostgreSQL."""
        RBACEnforcer.check_permission(ctx, "add_device")
        safe_host = AISafeGuardrails.sanitize_hostname(hostname)
        safe_ip = AISafeGuardrails.sanitize_mgmt_ip(mgmt_ip)
        safe_port = AISafeGuardrails.sanitize_ssh_port(ssh_port)
        norm_vendor = vendor.lower().strip()
        if norm_vendor not in ("cisco", "aruba"):
            raise SwitchMCPError(f"Unsupported vendor '{vendor}'. Allowed: cisco, aruba")

        os_version: str | None = None
        serial_number: str | None = None
        stack_count = 1
        discovered_facts: dict[str, Any] | None = None
        ssh_latency_ms: int | None = None

        if verify_ssh:
            start = time.perf_counter()
            probe_spec = DeviceConnectionSpec(
                device_id="onboarding-probe",
                hostname=safe_host,
                mgmt_ip=safe_ip,
                port=safe_port,
                vendor=norm_vendor,
                model=model,
                is_stacked=is_stacked,
                username=ssh_username,
                password=ssh_password,
                enable_secret=enable_secret,
                ssh_private_key=ssh_private_key,
                connect_timeout=self.settings.ssh_connect_timeout,
                command_timeout=self.settings.ssh_command_timeout,
            )
            adapter = SwitchAdapterFactory.create(probe_spec)
            async with adapter:
                facts = await adapter.get_facts()
            ssh_latency_ms = int((time.perf_counter() - start) * 1000)
            os_version = facts.os_version
            serial_number = facts.serial_number
            is_stacked = facts.is_stacked
            stack_count = max(len(facts.stack_members), 1)
            discovered_facts = facts.model_dump()

        vault_path = f"{self.settings.vault_switch_creds_prefix}/{safe_host}"
        await self.vault.store_switch_credentials(
            vault_path=vault_path,
            creds=SwitchCredentials(
                username=ssh_username,
                password=ssh_password,
                enable_secret=enable_secret,
                ssh_private_key=ssh_private_key,
            ),
        )
        site_id = await self.repo.ensure_site(site_code=site_code)
        saved = await self.repo.add_device(
            site_id=site_id,
            hostname=safe_host,
            mgmt_ip=safe_ip,
            ssh_port=safe_port,
            vendor=norm_vendor,
            model=model,
            os_version=os_version,
            serial_number=serial_number,
            is_stacked=is_stacked,
            stack_count=stack_count,
            vault_secret_path=vault_path,
            status="online" if verify_ssh else "unverified",
        )
        audit_id = await self.audit.record_event(
            ctx=ctx,
            tool_name="add_device",
            parameters={
                "hostname": safe_host,
                "mgmt_ip": safe_ip,
                "ssh_port": safe_port,
                "vendor": norm_vendor,
                "model": model,
                "site_code": site_code,
                "verify_ssh": verify_ssh,
            },
            device_hostname=safe_host,
            result_status="success",
            result_summary=f"Onboarded {norm_vendor} {model} switch '{safe_host}' ({safe_ip}:{safe_port}).",
            risk_level=RiskLevel.LOW.value,
        )
        return {
            "status": "success",
            "hostname": safe_host,
            "summary": f"Switch '{safe_host}' registered with Vault secrets and {'verified via live SSH' if verify_ssh else 'pending SSH check'}.",
            "risk": RiskLevel.LOW.value,
            "recommendations": [] if verify_ssh else [f"Run test_ssh_connection('{safe_host}') to verify SSH handshake."],
            "audit_id": audit_id,
            "data": {
                "device": saved,
                "ssh_verified": verify_ssh,
                "ssh_latency_ms": ssh_latency_ms,
                "discovered_facts": discovered_facts,
            },
        }

    async def test_ssh_connection(self, ctx: RequestContext, hostname: str) -> dict[str, Any]:
        """Verify live SSH handshake, enable privilege, and OS facts for a registered switch."""
        async def _probe(adapter: SwitchAdapter | None):
            t0 = time.perf_counter()
            facts = await adapter.get_facts()
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            return (
                f"SSH connection to {hostname} ({adapter.spec.mgmt_ip}:{adapter.spec.port}) succeeded in {elapsed_ms}ms.",
                {
                    "ssh_connected": True,
                    "mgmt_ip": adapter.spec.mgmt_ip,
                    "ssh_port": adapter.spec.port,
                    "roundtrip_ms": elapsed_ms,
                    "facts": facts.model_dump(),
                },
                [],
            )

        return await self.execute_read_tool(
            ctx,
            "test_ssh_connection",
            hostname,
            {"hostname": hostname},
            _probe,
        )

    async def decommission_device(
        self,
        ctx: RequestContext,
        hostname: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Remove a switch from PostgreSQL inventory and purge its Vault secret (HIGH risk)."""
        RBACEnforcer.check_permission(ctx, "remove_device")
        device = await self.repo.get_device_by_hostname(hostname)
        if not approval_id:
            cr = await self.approval.create_change_request(
                ctx=ctx,
                device_id=str(device.id),
                tool_name="remove_device",
                parameters={"hostname": hostname},
                cli_commands=[f"! Decommission switch {hostname} ({device.mgmt_ip}) from MCP inventory"],
                risk=RiskLevel.HIGH,
            )
            audit_id = await self.audit.record_event(
                ctx=ctx,
                tool_name="remove_device",
                parameters={"hostname": hostname},
                device_hostname=hostname,
                result_status="pending_approval",
                result_summary=f"Decommission requires 2 approvals ({cr['request_code']}).",
                risk_level=RiskLevel.HIGH.value,
                approval_id=cr["request_code"],
            )
            return {
                "status": "pending_approval",
                "hostname": hostname,
                "summary": f"Execution paused: removing switch '{hostname}' requires 2 approvals ({cr['request_code']}).",
                "risk": RiskLevel.HIGH.value,
                "recommendations": [f"Approve via approve_change('{cr['request_code']}') twice before re-running remove_device."],
                "audit_id": audit_id,
                "change_request": cr,
            }

        await self.approval.verify_approved_execution(approval_id, "remove_device")
        vault_path = await self.repo.remove_device(hostname)
        await self.vault.delete_switch_credentials(vault_path)
        await self.approval.mark_executed(approval_id)
        audit_id = await self.audit.record_event(
            ctx=ctx,
            tool_name="remove_device",
            parameters={"hostname": hostname},
            device_hostname=hostname,
            result_status="success",
            result_summary=f"Removed switch '{hostname}' and purged Vault secret '{vault_path}'.",
            risk_level=RiskLevel.HIGH.value,
            approval_id=approval_id,
        )
        return {
            "status": "success",
            "hostname": hostname,
            "summary": f"Switch '{hostname}' decommissioned from inventory and Vault.",
            "risk": RiskLevel.HIGH.value,
            "recommendations": [],
            "audit_id": audit_id,
            "approval_id": approval_id,
        }

    async def execute_read_tool(
        self,
        ctx: RequestContext,
        tool_name: str,
        hostname: str | None,
        parameters: dict[str, Any],
        action: Callable[[SwitchAdapter | None], Awaitable[tuple[str, Any, list[str]]]],
    ) -> dict[str, Any]:
        """Execute a LOW-risk read-only tool with RBAC, tracing, and immutable audit."""
        RBACEnforcer.check_permission(ctx, tool_name)
        risk = RBACEnforcer.get_tool_risk(tool_name)
        start = time.perf_counter()
        vendor = "platform"

        try:
            if hostname:
                adapter = await self.open_adapter(hostname)
                vendor = adapter.spec.vendor
                async with adapter:
                    summary, data, recs = await action(adapter)
            else:
                summary, data, recs = await action(None)

            audit_id = await self.audit.record_event(
                ctx=ctx,
                tool_name=tool_name,
                parameters=parameters,
                device_hostname=hostname,
                result_status="success",
                result_summary=summary,
                risk_level=risk.value,
            )
            MCP_TOOL_CALLS_TOTAL.labels(tool_name=tool_name, role=ctx.role, status="success", risk_level=risk.value).inc()
            return {
                "status": "success",
                "hostname": hostname or "GLOBAL",
                "summary": summary,
                "risk": risk.value,
                "recommendations": recs,
                "audit_id": audit_id,
                "data": data,
            }
        except SwitchMCPError as exc:
            audit_id = await self.audit.record_event(
                ctx=ctx,
                tool_name=tool_name,
                parameters=parameters,
                device_hostname=hostname,
                result_status="error",
                result_summary=exc.message,
                risk_level=risk.value,
            )
            MCP_TOOL_CALLS_TOTAL.labels(tool_name=tool_name, role=ctx.role, status="error", risk_level=risk.value).inc()
            return {
                "status": "error",
                "hostname": hostname or "GLOBAL",
                "summary": exc.message,
                "risk": risk.value,
                "recommendations": ["Verify device reachability, RBAC permissions, and parameters."],
                "audit_id": audit_id,
                "error_code": exc.code,
                "details": exc.details,
            }
        finally:
            MCP_TOOL_DURATION_SECONDS.labels(tool_name=tool_name, vendor=vendor).observe(time.perf_counter() - start)

    async def execute_change_tool(
        self,
        ctx: RequestContext,
        tool_name: str,
        hostname: str,
        parameters: dict[str, Any],
        cli_builder: Callable[[str], list[str]],
        approval_id: str | None = None,
        change_ticket: str | None = None,
    ) -> dict[str, Any]:
        """Execute a mutating tool through Guardrails, Risk Assessment, Approval Workflow, Distributed Lock, and Audit."""
        RBACEnforcer.check_permission(ctx, tool_name)
        risk = RBACEnforcer.get_tool_risk(tool_name)
        device = await self.repo.get_device_by_hostname(hostname)
        commands = cli_builder(device.vendor)

        # Step 1: AI Safe Guardrails check
        try:
            AISafeGuardrails.inspect_commands(tool_name, commands, vendor=device.vendor)
        except GuardrailViolationError as exc:
            audit_id = await self.audit.record_event(
                ctx=ctx,
                tool_name=tool_name,
                parameters=parameters,
                device_hostname=hostname,
                result_status="blocked",
                result_summary=exc.message,
                risk_level=RiskLevel.CRITICAL.value,
            )
            return {
                "status": "blocked",
                "hostname": hostname,
                "summary": exc.message,
                "risk": RiskLevel.CRITICAL.value,
                "recommendations": exc.details.get("change_plan", []),
                "audit_id": audit_id,
                "cli_commands": exc.details.get("cli_commands", []),
            }

        # Step 2: Approval enforcement for MEDIUM / HIGH / CRITICAL
        if risk != RiskLevel.LOW:
            if not approval_id:
                cr = await self.approval.create_change_request(
                    ctx=ctx,
                    device_id=str(device.id),
                    tool_name=tool_name,
                    parameters=parameters,
                    cli_commands=commands,
                    risk=risk,
                    change_ticket=change_ticket,
                )
                audit_id = await self.audit.record_event(
                    ctx=ctx,
                    tool_name=tool_name,
                    parameters=parameters,
                    device_hostname=hostname,
                    result_status="pending_approval",
                    result_summary=f"Change request {cr['request_code']} created ({risk.value} risk).",
                    risk_level=risk.value,
                    approval_id=cr["request_code"],
                )
                return {
                    "status": "pending_approval",
                    "hostname": hostname,
                    "summary": f"Execution paused: {risk.value} risk tool '{tool_name}' requires approval ({cr['request_code']}).",
                    "risk": risk.value,
                    "recommendations": [
                        f"Approve via approve_change(request_code='{cr['request_code']}')",
                        f"Re-invoke {tool_name} with approval_id='{cr['request_code']}' once APPROVED.",
                    ],
                    "audit_id": audit_id,
                    "change_request": cr,
                }
            await self.approval.verify_approved_execution(approval_id, tool_name)

        # Step 3: Acquire Redis distributed lock & execute on switch
        start = time.perf_counter()
        async with self.redis.device_lock(hostname):
            adapter = await self.open_adapter(hostname)
            async with adapter:
                pre_cfg = await adapter.backup_config("running")
                import hashlib
                await self.repo.save_backup(
                    device_id=str(device.id),
                    config_type="pre_change",
                    config_text=pre_cfg,
                    sha256_hash=hashlib.sha256(pre_cfg.encode("utf-8")).hexdigest(),
                    username=ctx.username,
                )
                output = await adapter.execute_config(commands, save_config=True)

        if approval_id:
            await self.approval.mark_executed(approval_id)

        audit_id = await self.audit.record_event(
            ctx=ctx,
            tool_name=tool_name,
            parameters=parameters,
            device_hostname=hostname,
            result_status="success",
            result_summary=f"Executed {tool_name} cleanly with pre-change snapshot.",
            risk_level=risk.value,
            approval_id=approval_id,
        )
        MCP_TOOL_CALLS_TOTAL.labels(tool_name=tool_name, role=ctx.role, status="success", risk_level=risk.value).inc()
        MCP_TOOL_DURATION_SECONDS.labels(tool_name=tool_name, vendor=device.vendor).observe(time.perf_counter() - start)
        return {
            "status": "success",
            "hostname": hostname,
            "summary": f"Executed '{tool_name}' on {hostname} ({device.vendor}) with pre-change backup.",
            "risk": risk.value,
            "recommendations": ["Verify operational state with get_interfaces or get_vlans."],
            "audit_id": audit_id,
            "approval_id": approval_id,
            "data": {"cli_output": output[:1000]},
        }
