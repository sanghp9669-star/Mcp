"""MCP Resources exposing real-time PostgreSQL & switch topology state."""

import json

from fastmcp import FastMCP
from sqlalchemy import text

from switch_mcp.security.auth import RequestContext
from switch_mcp.security.rbac import RBACEnforcer
from switch_mcp.services.network_service import NetworkService


def register_resources(
    mcp: FastMCP,
    svc: NetworkService,
    get_ctx: callable,
) -> None:
    """Register all 9 enterprise network:// MCP resources."""

    @mcp.resource("network://devices")
    async def resource_devices() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:devices")
        devices = await svc.repo.list_devices()
        return json.dumps({"devices": devices}, default=str)

    @mcp.resource("network://inventory")
    async def resource_inventory() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:inventory")
        async with svc.repo._db.read_session() as s:
            rows = (
                await s.execute(
                    text(
                        """
                        SELECT d.hostname, i.slot_name, i.model, i.serial_number, i.firmware_version
                        FROM inventory i JOIN devices d ON d.id = i.device_id
                        ORDER BY d.hostname, i.slot_name
                        """
                    )
                )
            ).mappings().all()
        return json.dumps({"inventory": [dict(r) for r in rows]}, default=str)

    @mcp.resource("network://vlans")
    async def resource_vlans() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:vlans")
        devices = await svc.repo.list_devices()
        return json.dumps({"scope": "campus-switches", "device_count": len(devices), "note": "Use get_vlans(hostname) for live switch VLAN tables."})

    @mcp.resource("network://configs")
    async def resource_configs() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:configs")
        async with svc.repo._db.read_session() as s:
            rows = (
                await s.execute(
                    text(
                        """
                        SELECT d.hostname, c.config_type, c.sha256_hash, c.collected_by, c.collected_at
                        FROM configs c JOIN devices d ON d.id = c.device_id
                        ORDER BY c.collected_at DESC LIMIT 100
                        """
                    )
                )
            ).mappings().all()
        return json.dumps({"configs": [dict(r) for r in rows]}, default=str)

    @mcp.resource("network://backups")
    async def resource_backups() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:backups")
        async with svc.repo._db.read_session() as s:
            rows = (
                await s.execute(
                    text(
                        """
                        SELECT b.id, d.hostname, b.backup_type, b.sha256_hash, b.created_at
                        FROM backups b JOIN devices d ON d.id = b.device_id
                        ORDER BY b.created_at DESC LIMIT 100
                        """
                    )
                )
            ).mappings().all()
        return json.dumps({"backups": [dict(r) for r in rows]}, default=str)

    @mcp.resource("network://health")
    async def resource_health() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:health")
        async with svc.repo._db.read_session() as s:
            rows = (
                await s.execute(
                    text(
                        """
                        SELECT d.hostname, h.cpu_5min_pct, h.memory_used_pct, h.temperature_celsius, h.stack_status, h.recorded_at
                        FROM health_reports h JOIN devices d ON d.id = h.device_id
                        ORDER BY h.recorded_at DESC LIMIT 100
                        """
                    )
                )
            ).mappings().all()
        return json.dumps({"health_reports": [dict(r) for r in rows]}, default=str)

    @mcp.resource("network://topology")
    async def resource_topology() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:topology")
        devices = await svc.repo.list_devices()
        return json.dumps({"nodes": devices, "discovery_protocols": ["CDP", "LLDP"]}, default=str)

    @mcp.resource("network://auditlogs")
    async def resource_auditlogs() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:auditlogs")
        logs = await svc.repo.query_audit_logs(limit=100)
        return json.dumps({"audit_logs": logs}, default=str)

    @mcp.resource("network://approvals")
    async def resource_approvals() -> str:
        ctx: RequestContext = get_ctx()
        RBACEnforcer.check_permission(ctx, "resource:approvals")
        pending = await svc.repo.list_pending_changes()
        return json.dumps({"pending_approvals": pending}, default=str)
