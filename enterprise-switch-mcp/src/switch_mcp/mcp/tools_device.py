"""MCP Device Inspection Tools (9 tools)."""

from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.services.network_service import NetworkService


def register_device_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def list_devices(vendor: str | None = None) -> dict[str, Any]:
        """List managed Cisco Catalyst and Aruba switches registered in inventory."""
        async def _act(_: SwitchAdapter | None):
            devices = await svc.repo.list_devices(vendor=vendor)
            return f"Retrieved {len(devices)} managed switches.", devices, []

        return await svc.execute_read_tool(get_ctx(), "list_devices", None, {"vendor": vendor}, _act)

    @mcp.tool()
    async def add_device(
        hostname: str,
        mgmt_ip: str,
        vendor: str,
        model: str,
        ssh_username: str,
        ssh_password: str,
        site_code: str = "HQ-CORE",
        ssh_port: int = 22,
        enable_secret: str | None = None,
        ssh_private_key: str | None = None,
        is_stacked: bool = False,
        verify_ssh: bool = True,
    ) -> dict[str, Any]:
        """Register a Cisco/Aruba switch, store SSH secrets in Vault, and verify live SSH connectivity."""
        return await svc.onboard_device(
            get_ctx(),
            hostname=hostname,
            mgmt_ip=mgmt_ip,
            vendor=vendor,
            model=model,
            site_code=site_code,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            enable_secret=enable_secret,
            ssh_private_key=ssh_private_key,
            ssh_port=ssh_port,
            is_stacked=is_stacked,
            verify_ssh=verify_ssh,
        )

    @mcp.tool()
    async def test_ssh_connection(hostname: str) -> dict[str, Any]:
        """Test live SSH handshake, Vault credential fetch, and CLI prompt readiness on a switch."""
        return await svc.test_ssh_connection(get_ctx(), hostname=hostname)

    @mcp.tool()
    async def remove_device(hostname: str, approval_id: str | None = None) -> dict[str, Any]:
        """Decommission a switch from inventory and purge Vault credentials (HIGH risk: 2 approvals)."""
        return await svc.decommission_device(get_ctx(), hostname=hostname, approval_id=approval_id)

    @mcp.tool()
    async def get_device_info(hostname: str) -> dict[str, Any]:
        """Retrieve live hardware model, OS version, serial, uptime, and stack members."""
        async def _act(adapter: SwitchAdapter | None):
            facts = await adapter.get_facts()
            return f"Collected facts for {hostname} ({facts.model}, OS {facts.os_version}).", facts.model_dump(), []

        return await svc.execute_read_tool(get_ctx(), "get_device_info", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_running_config(hostname: str) -> dict[str, Any]:
        """Fetch live running configuration from the switch."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("running")
            return f"Retrieved running-config ({len(cfg.splitlines())} lines).", {"config": cfg}, []

        return await svc.execute_read_tool(get_ctx(), "get_running_config", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_startup_config(hostname: str) -> dict[str, Any]:
        """Fetch saved startup configuration from NVRAM/flash."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("startup")
            return f"Retrieved startup-config ({len(cfg.splitlines())} lines).", {"config": cfg}, []

        return await svc.execute_read_tool(get_ctx(), "get_startup_config", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_interfaces(hostname: str) -> dict[str, Any]:
        """List all switch interfaces with admin/oper status, VLANs, and error counters."""
        async def _act(adapter: SwitchAdapter | None):
            intfs = await adapter.get_interfaces()
            up_cnt = sum(1 for i in intfs if i.oper_status == "up")
            return f"{up_cnt}/{len(intfs)} interfaces operational on {hostname}.", [i.model_dump() for i in intfs], []

        return await svc.execute_read_tool(get_ctx(), "get_interfaces", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_neighbors(hostname: str) -> dict[str, Any]:
        """Discover CDP and LLDP adjacent network devices."""
        async def _act(adapter: SwitchAdapter | None):
            nbrs = await adapter.get_neighbors()
            return f"Discovered {len(nbrs)} CDP/LLDP neighbors on {hostname}.", [n.model_dump() for n in nbrs], []

        return await svc.execute_read_tool(get_ctx(), "get_neighbors", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_mac_table(hostname: str) -> dict[str, Any]:
        """Retrieve Layer 2 MAC address table."""
        async def _act(adapter: SwitchAdapter | None):
            macs = await adapter.get_mac_table()
            return f"Retrieved {len(macs)} MAC entries from {hostname}.", macs, []

        return await svc.execute_read_tool(get_ctx(), "get_mac_table", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_arp_table(hostname: str) -> dict[str, Any]:
        """Retrieve Layer 3 ARP table."""
        async def _act(adapter: SwitchAdapter | None):
            arp = await adapter.get_arp_table()
            return f"Retrieved {len(arp)} ARP entries from {hostname}.", arp, []

        return await svc.execute_read_tool(get_ctx(), "get_arp_table", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def get_logs(hostname: str, lines: int = 100) -> dict[str, Any]:
        """Retrieve recent buffered syslog messages from the switch."""
        async def _act(adapter: SwitchAdapter | None):
            logs = await adapter.get_logs(lines=min(max(lines, 1), 500))
            return f"Fetched last {len(logs)} syslog lines from {hostname}.", {"logs": logs}, []

        return await svc.execute_read_tool(get_ctx(), "get_logs", hostname, {"hostname": hostname, "lines": lines}, _act)
