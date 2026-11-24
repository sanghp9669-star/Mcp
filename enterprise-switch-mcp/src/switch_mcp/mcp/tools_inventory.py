"""MCP Hardware Inventory & Lifecycle Tools (4 tools)."""

from dataclasses import asdict
from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.services.network_service import NetworkService


def register_inventory_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def collect_inventory(hostname: str) -> dict[str, Any]:
        """Collect chassis, stack member, module, and SFP serial inventory."""
        async def _act(adapter: SwitchAdapter | None):
            items = [asdict(i) for i in await adapter.collect_inventory()]
            return f"Collected {len(items)} hardware inventory items from {hostname}.", items, []

        return await svc.execute_read_tool(get_ctx(), "collect_inventory", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def collect_serials(hostname: str) -> dict[str, Any]:
        """Collect serial numbers for switch chassis and stack members."""
        async def _act(adapter: SwitchAdapter | None):
            items = await adapter.collect_inventory()
            serials = [{"slot": i.slot, "model": i.model, "serial_number": i.serial_number} for i in items if i.serial_number]
            return f"Collected {len(serials)} serial numbers from {hostname}.", serials, []

        return await svc.execute_read_tool(get_ctx(), "collect_serials", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def collect_software_versions(hostname: str) -> dict[str, Any]:
        """Collect OS software image versions and stack firmware consistency."""
        async def _act(adapter: SwitchAdapter | None):
            facts = await adapter.get_facts()
            return (
                f"{hostname} running {facts.vendor} {facts.model} OS {facts.os_version}.",
                {"vendor": facts.vendor, "model": facts.model, "os_version": facts.os_version, "is_stacked": facts.is_stacked},
                [],
            )

        return await svc.execute_read_tool(get_ctx(), "collect_software_versions", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def collect_uptime(hostname: str) -> dict[str, Any]:
        """Collect system uptime in seconds and human-readable days."""
        async def _act(adapter: SwitchAdapter | None):
            facts = await adapter.get_facts()
            days = round(facts.uptime_seconds / 86400, 2)
            return f"{hostname} uptime is {days} days ({facts.uptime_seconds}s).", {"uptime_seconds": facts.uptime_seconds, "uptime_days": days}, []

        return await svc.execute_read_tool(get_ctx(), "collect_uptime", hostname, {"hostname": hostname}, _act)
