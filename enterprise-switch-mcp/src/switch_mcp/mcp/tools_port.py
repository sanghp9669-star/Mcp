"""MCP Port Management Tools (8 tools)."""

from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.services.network_service import NetworkService


def register_port_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def get_ports(hostname: str) -> dict[str, Any]:
        """Retrieve interface/port summary for a switch."""
        async def _act(adapter: SwitchAdapter | None):
            ports = await adapter.get_interfaces()
            return f"Retrieved {len(ports)} ports from {hostname}.", [p.model_dump() for p in ports], []

        return await svc.execute_read_tool(get_ctx(), "get_ports", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def shutdown_port(
        hostname: str,
        interface: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Administratively shut down a switch port (HIGH risk: requires 2 approvals)."""
        intf = AISafeGuardrails.sanitize_interface(interface)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"interface {intf}", "disable", "exit"]
            return [f"interface {intf}", "shutdown", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "shutdown_port",
            hostname,
            {"hostname": hostname, "interface": intf},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def no_shutdown_port(
        hostname: str,
        interface: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Administratively enable a switch port (MEDIUM risk: requires 1 approval)."""
        intf = AISafeGuardrails.sanitize_interface(interface)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"interface {intf}", "enable", "exit"]
            return [f"interface {intf}", "no shutdown", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "no_shutdown_port",
            hostname,
            {"hostname": hostname, "interface": intf},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def set_access_vlan(
        hostname: str,
        interface: str,
        vlan_id: int,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Configure a port as an access port in the specified VLAN (MEDIUM risk)."""
        intf = AISafeGuardrails.sanitize_interface(interface)
        vid = AISafeGuardrails.sanitize_vlan_id(vlan_id)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"vlan {vid}", f"untagged {intf}", "exit"]
            return [f"interface {intf}", "switchport mode access", f"switchport access vlan {vid}", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "set_access_vlan",
            hostname,
            {"hostname": hostname, "interface": intf, "vlan_id": vid},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def set_trunk(
        hostname: str,
        interface: str,
        native_vlan: int,
        allowed_vlans: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Configure an 802.1Q trunk port with native and allowed VLANs (HIGH risk)."""
        intf = AISafeGuardrails.sanitize_interface(interface)
        nvid = AISafeGuardrails.sanitize_vlan_id(native_vlan)
        allowed = AISafeGuardrails.sanitize_allowed_vlans(allowed_vlans)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                cmds = [f"vlan {nvid}", f"untagged {intf}", "exit"]
                for token in allowed.split(","):
                    if "-" not in token:
                        cmds.extend([f"vlan {int(token)}", f"tagged {intf}", "exit"])
                return cmds
            return [
                f"interface {intf}",
                "switchport trunk encapsulation dot1q",
                "switchport mode trunk",
                f"switchport trunk native vlan {nvid}",
                f"switchport trunk allowed vlan {allowed}",
                "exit",
            ]

        return await svc.execute_change_tool(
            get_ctx(),
            "set_trunk",
            hostname,
            {"hostname": hostname, "interface": intf, "native_vlan": nvid, "allowed_vlans": allowed},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def set_description(
        hostname: str,
        interface: str,
        description: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Update interface description label (MEDIUM risk)."""
        intf = AISafeGuardrails.sanitize_interface(interface)
        desc = AISafeGuardrails.sanitize_description(description)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"interface {intf}", f'name "{desc}"', "exit"]
            return [f"interface {intf}", f"description {desc}", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "set_description",
            hostname,
            {"hostname": hostname, "interface": intf, "description": desc},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def enable_port_security(
        hostname: str,
        interface: str,
        max_macs: int = 2,
        violation_mode: str = "restrict",
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Enable port-security on an access interface (MEDIUM risk)."""
        intf = AISafeGuardrails.sanitize_interface(interface)
        limit = min(max(int(max_macs), 1), 32)
        mode = violation_mode if violation_mode in ("protect", "restrict", "shutdown") else "restrict"

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"port-security {intf} learn-mode limited-continuous address-limit {limit} action send-alarm"]
            return [
                f"interface {intf}",
                "switchport port-security",
                f"switchport port-security maximum {limit}",
                f"switchport port-security violation {mode}",
                "switchport port-security mac-address sticky",
                "exit",
            ]

        return await svc.execute_change_tool(
            get_ctx(),
            "enable_port_security",
            hostname,
            {"hostname": hostname, "interface": intf, "max_macs": limit, "violation_mode": mode},
            _cli,
            approval_id=approval_id,
        )

    @mcp.tool()
    async def disable_port_security(
        hostname: str,
        interface: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Disable port-security on an interface (HIGH risk: weakens NAC posture)."""
        intf = AISafeGuardrails.sanitize_interface(interface)

        def _cli(vendor: str) -> list[str]:
            if vendor == "aruba":
                return [f"no port-security {intf}"]
            return [f"interface {intf}", "no switchport port-security", "exit"]

        return await svc.execute_change_tool(
            get_ctx(),
            "disable_port_security",
            hostname,
            {"hostname": hostname, "interface": intf},
            _cli,
            approval_id=approval_id,
        )
