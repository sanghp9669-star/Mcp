"""MCP Layer 1/2/3 Troubleshooting Tools (6 tools)."""

from collections import defaultdict
from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.services.network_service import NetworkService


def register_troubleshoot_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def interface_errors(hostname: str) -> dict[str, Any]:
        """Identify switch ports experiencing input, output, or CRC frame errors."""
        async def _act(adapter: SwitchAdapter | None):
            intfs = await adapter.get_interfaces()
            faulty = [i.model_dump() for i in intfs if (i.input_errors + i.output_errors + i.crc_errors) > 0]
            recs = ["Run cable_diagnostics on copper ports with CRC errors."] if faulty else []
            return f"Found {len(faulty)} interfaces with physical/CRC errors on {hostname}.", faulty, recs

        return await svc.execute_read_tool(get_ctx(), "interface_errors", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def identify_loop(hostname: str) -> dict[str, Any]:
        """Detect Layer 2 switching loops via STP topology changes, MAC flaps, and error storms."""
        async def _act(adapter: SwitchAdapter | None):
            stp = await adapter.get_spanning_tree()
            logs = await adapter.get_logs(150)
            loop_logs = [ln for ln in logs if any(k in ln.upper() for k in ("MACFLAP", "LOOP", "ERRDISABLE", "BPDU"))]
            suspected = len(loop_logs) > 0 or len(stp.get("topology_changes", [])) > 3
            recs = ["Inspect edge ports for missing BPDU Guard and verify root bridge placement."] if suspected else []
            return (
                f"Loop analysis complete: {'POTENTIAL LOOP DETECTED' if suspected else 'No active loop indicators'}.",
                {"suspected_loop": suspected, "loop_syslog_hits": loop_logs, "stp": stp},
                recs,
            )

        return await svc.execute_read_tool(get_ctx(), "identify_loop", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def check_uplink(hostname: str) -> dict[str, Any]:
        """Verify operational status and error counters on trunk/uplink ports with CDP/LLDP neighbors."""
        async def _act(adapter: SwitchAdapter | None):
            nbrs = await adapter.get_neighbors()
            intfs = {i.name: i for i in await adapter.get_interfaces()}
            uplinks = []
            for n in nbrs:
                intf = intfs.get(n.local_interface)
                uplinks.append({
                    "local_interface": n.local_interface,
                    "neighbor": n.neighbor_device,
                    "neighbor_port": n.neighbor_interface,
                    "oper_status": intf.oper_status if intf else "unknown",
                    "crc_errors": intf.crc_errors if intf else 0,
                })
            return f"Checked {len(uplinks)} uplink connections on {hostname}.", uplinks, []

        return await svc.execute_read_tool(get_ctx(), "check_uplink", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def cable_diagnostics(hostname: str, interface: str) -> dict[str, Any]:
        """Run TDR cable diagnostics on a switch port to detect open/short pairs."""
        async def _act(adapter: SwitchAdapter | None):
            res = await adapter.run_cable_diagnostics(interface)
            return f"Completed TDR cable diagnostics on {hostname} {interface}.", res, []

        return await svc.execute_read_tool(get_ctx(), "cable_diagnostics", hostname, {"hostname": hostname, "interface": interface}, _act)

    @mcp.tool()
    async def spanning_tree_check(hostname: str) -> dict[str, Any]:
        """Inspect STP/RSTP root bridge status, blocked ports, and recent TCN events."""
        async def _act(adapter: SwitchAdapter | None):
            stp = await adapter.get_spanning_tree()
            return f"Retrieved Spanning Tree state for {hostname}.", stp, []

        return await svc.execute_read_tool(get_ctx(), "spanning_tree_check", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def mac_flapping_detection(hostname: str) -> dict[str, Any]:
        """Detect MAC addresses moving rapidly across multiple ports or syslog MACFLAP alerts."""
        async def _act(adapter: SwitchAdapter | None):
            macs = await adapter.get_mac_table()
            logs = await adapter.get_logs(150)
            mac_ports: dict[str, set[str]] = defaultdict(set)
            for row in macs:
                mac_ports[f"{row['vlan']}:{row['mac_address']}"].add(row["port"])
            multi_port = [{"key": k, "ports": sorted(v)} for k, v in mac_ports.items() if len(v) > 1]
            syslog_flaps = [ln for ln in logs if "FLAP" in ln.upper() or "MOVED" in ln.upper()]
            return (
                f"Detected {len(multi_port)} multi-port MACs and {len(syslog_flaps)} flap logs.",
                {"multi_port_macs": multi_port, "syslog_flaps": syslog_flaps},
                ["Enable port-security and verify LACP/EtherChannel bundling on flapping ports."] if (multi_port or syslog_flaps) else [],
            )

        return await svc.execute_read_tool(get_ctx(), "mac_flapping_detection", hostname, {"hostname": hostname}, _act)
