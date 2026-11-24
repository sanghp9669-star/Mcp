"""MCP System & Stack Health Telemetry Tools (4 tools)."""

from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.services.network_service import NetworkService


def register_health_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def cpu_health(hostname: str) -> dict[str, Any]:
        """Monitor 5s, 1m, and 5m switch CPU utilization."""
        async def _act(adapter: SwitchAdapter | None):
            h = await adapter.health_check()
            recs = ["High CPU (>75%): inspect spanning-tree TCN or broadcast storms."] if h.cpu_5min_pct > 75 else []
            return f"{hostname} CPU 5m={h.cpu_5min_pct}%.", {"cpu_5sec": h.cpu_5sec_pct, "cpu_1min": h.cpu_1min_pct, "cpu_5min": h.cpu_5min_pct}, recs

        return await svc.execute_read_tool(get_ctx(), "cpu_health", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def memory_health(hostname: str) -> dict[str, Any]:
        """Monitor processor DRAM utilization and free bytes."""
        async def _act(adapter: SwitchAdapter | None):
            h = await adapter.health_check()
            recs = ["High memory usage (>85%): schedule maintenance review."] if h.memory_used_pct > 85 else []
            return f"{hostname} memory used={h.memory_used_pct}%.", {"memory_used_pct": h.memory_used_pct, "memory_free_bytes": h.memory_free_bytes}, recs

        return await svc.execute_read_tool(get_ctx(), "memory_health", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def temperature_health(hostname: str) -> dict[str, Any]:
        """Monitor chassis thermal sensors and alarm thresholds."""
        async def _act(adapter: SwitchAdapter | None):
            h = await adapter.health_check()
            recs = ["Thermal warning: inspect rack airflow and fan modules."] if h.temperature_status != "OK" else []
            return f"{hostname} temperature={h.temperature_celsius}C ({h.temperature_status}).", {"temperature_celsius": h.temperature_celsius, "status": h.temperature_status}, recs

        return await svc.execute_read_tool(get_ctx(), "temperature_health", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def stack_health(hostname: str) -> dict[str, Any]:
        """Monitor Cisco StackWise/FlexStack or Aruba VSF/Backplane member roles and ring status."""
        async def _act(adapter: SwitchAdapter | None):
            h = await adapter.health_check()
            recs = ["Stack degraded: inspect StackWise/VSF cables and standby member."] if h.stack_status == "degraded" else []
            return f"{hostname} stack status={h.stack_status} ({len(h.stack_members_health)} members).", {"stack_status": h.stack_status, "members": h.stack_members_health}, recs

        return await svc.execute_read_tool(get_ctx(), "stack_health", hostname, {"hostname": hostname}, _act)
