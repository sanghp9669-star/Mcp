"""MCP VLAN Management Tools (4 tools)."""

from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.services.network_service import NetworkService


def register_vlan_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def get_vlans(hostname: str) -> dict[str, Any]:
        """List all configured VLANs and port memberships on the switch."""
        async def _act(adapter: SwitchAdapter | None):
            vlans = await adapter.get_vlans()
            return f"Found {len(vlans)} VLANs on {hostname}.", [v.model_dump() for v in vlans], []

        return await svc.execute_read_tool(get_ctx(), "get_vlans", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def create_vlan(
        hostname: str,
        vlan_id: int,
        name: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a VLAN (MEDIUM risk: requires 1 approval)."""
        vid = AISafeGuardrails.sanitize_vlan_id(vlan_id)
        vname = AISafeGuardrails.sanitize_vlan_name(name)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"vlan {vid}", f"name {vname}", "exit"]
            return [f"vlan {vid}", f"name {vname}", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "create_vlan",
            hostname,
            {"hostname": hostname, "vlan_id": vid, "name": vname},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def delete_vlan(
        hostname: str,
        vlan_id: int,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Delete a VLAN (HIGH risk: requires 2 distinct approvals)."""
        vid = AISafeGuardrails.sanitize_vlan_id(vlan_id)

        def _cli(vendor: str) -> list[str]:
            return [f"no vlan {vid}"]

        return await svc.execute_change_tool(
            get_ctx(),
            "delete_vlan",
            hostname,
            {"hostname": hostname, "vlan_id": vid},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def rename_vlan(
        hostname: str,
        vlan_id: int,
        new_name: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Rename an existing VLAN (MEDIUM risk: requires 1 approval)."""
        vid = AISafeGuardrails.sanitize_vlan_id(vlan_id)
        vname = AISafeGuardrails.sanitize_vlan_name(new_name)

        def _cli(vendor: str) -> list[str]:
            return [f"vlan {vid}", f"name {vname}", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "rename_vlan",
            hostname,
            {"hostname": hostname, "vlan_id": vid, "new_name": vname},
            _cli,
            approval_id=approval_id,
        )
