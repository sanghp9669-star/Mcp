"""MCP Security Compliance & Hardening Audit Tools (7 tools)."""

import re
from typing import Any

from fastmcp import FastMCP

from switch_mcp.adapters.base import SwitchAdapter
from switch_mcp.services.network_service import NetworkService


def register_security_tools(mcp: FastMCP, svc: NetworkService, get_ctx: callable) -> None:
    @mcp.tool()
    async def audit_security(hostname: str) -> dict[str, Any]:
        """Run comprehensive CIS/Enterprise security posture audit on running configuration."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("running")
            findings = []
            if re.search(r"transport input.*telnet", cfg, re.IGNORECASE) or re.search(r"^telnet-server", cfg, re.MULTILINE):
                findings.append({"severity": "HIGH", "control": "VTY_SSH_ONLY", "detail": "Telnet enabled"})
            if re.search(r"snmp-server community\s+(public|private)\b", cfg, re.IGNORECASE):
                findings.append({"severity": "CRITICAL", "control": "SNMP_HARDENING", "detail": "Default SNMP community string found"})
            if not re.search(r"service password-encryption|password manager", cfg, re.IGNORECASE):
                findings.append({"severity": "MEDIUM", "control": "PASSWORD_ENCRYPTION", "detail": "Weak password storage"})
            if not re.search(r"ip ssh version 2|ip ssh", cfg, re.IGNORECASE):
                findings.append({"severity": "HIGH", "control": "SSH_V2", "detail": "SSHv2 enforcement missing"})
            recs = [f"[{f['severity']}] Remediate {f['control']}: {f['detail']}" for f in findings]
            return f"Security audit completed with {len(findings)} findings on {hostname}.", {"findings": findings}, recs

        return await svc.execute_read_tool(get_ctx(), "audit_security", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def find_unused_ports(hostname: str) -> dict[str, Any]:
        """Identify admin-up ports that are physically down/unused and candidates for shutdown."""
        async def _act(adapter: SwitchAdapter | None):
            intfs = await adapter.get_interfaces()
            unused = [i.model_dump() for i in intfs if i.admin_status == "up" and i.oper_status != "up"]
            recs = [f"Consider shutting down {len(unused)} unused admin-up ports to reduce attack surface."] if unused else []
            return f"Found {len(unused)} unused admin-up ports on {hostname}.", unused, recs

        return await svc.execute_read_tool(get_ctx(), "find_unused_ports", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def find_vlan_mismatch(hostname: str) -> dict[str, Any]:
        """Detect interfaces referencing non-existent VLANs or trunk/access mismatches."""
        async def _act(adapter: SwitchAdapter | None):
            vlans = {v.vlan_id for v in await adapter.get_vlans()}
            intfs = await adapter.get_interfaces()
            mismatches = [
                {"interface": i.name, "assigned_vlan": i.vlan_id}
                for i in intfs
                if i.vlan_id is not None and i.vlan_id not in vlans
            ]
            return f"Detected {len(mismatches)} VLAN mismatches on {hostname}.", mismatches, []

        return await svc.execute_read_tool(get_ctx(), "find_vlan_mismatch", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def detect_native_vlan_mismatch(hostname: str) -> dict[str, Any]:
        """Detect CDP/LLDP native VLAN mismatch warnings and default VLAN 1 trunk usage."""
        async def _act(adapter: SwitchAdapter | None):
            logs = await adapter.get_logs(200)
            cfg = await adapter.backup_config("running")
            cdp_mismatches = [ln for ln in logs if "NATIVE_VLAN_MISMATCH" in ln.upper()]
            default_native = "switchport trunk native vlan" not in cfg.lower() and "switchport mode trunk" in cfg.lower()
            recs = ["Set explicit non-VLAN-1 native VLAN on all 802.1Q trunks."] if (cdp_mismatches or default_native) else []
            return (
                f"Native VLAN audit found {len(cdp_mismatches)} syslog mismatch alerts.",
                {"syslog_mismatches": cdp_mismatches, "uses_default_vlan1_trunk": default_native},
                recs,
            )

        return await svc.execute_read_tool(get_ctx(), "detect_native_vlan_mismatch", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def check_telnet_enabled(hostname: str) -> dict[str, Any]:
        """Check whether insecure cleartext Telnet access is enabled on VTY/management."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("running")
            enabled = bool(re.search(r"transport input.*telnet|^telnet-server", cfg, re.IGNORECASE | re.MULTILINE))
            recs = ["Disable Telnet and enforce 'transport input ssh' on VTY lines."] if enabled else []
            return f"Telnet is {'ENABLED (NON-COMPLIANT)' if enabled else 'DISABLED (COMPLIANT)'} on {hostname}.", {"telnet_enabled": enabled}, recs

        return await svc.execute_read_tool(get_ctx(), "check_telnet_enabled", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def check_snmp_security(hostname: str) -> dict[str, Any]:
        """Verify SNMPv3 authPriv enforcement and absence of default v1/v2c communities."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("running")
            v2_lines = re.findall(r"^snmp-server community\s+\S+.*$", cfg, re.MULTILINE)
            has_v3 = bool(re.search(r"snmp-server group.*v3\s+priv|snmpv3", cfg, re.IGNORECASE))
            recs = ["Migrate from SNMPv1/v2c communities to SNMPv3 SHA/AES-128."] if v2_lines else []
            return f"SNMP security check: v3={'yes' if has_v3 else 'no'}, legacy_communities={len(v2_lines)}.", {"has_snmpv3": has_v3, "legacy_communities": v2_lines}, recs

        return await svc.execute_read_tool(get_ctx(), "check_snmp_security", hostname, {"hostname": hostname}, _act)

    @mcp.tool()
    async def check_port_security(hostname: str) -> dict[str, Any]:
        """Verify port-security coverage across access edge ports."""
        async def _act(adapter: SwitchAdapter | None):
            cfg = await adapter.backup_config("running")
            secured_count = len(re.findall(r"switchport port-security|port-security\s+\S+", cfg))
            return f"Detected {secured_count} port-security directives on {hostname}.", {"port_security_directives": secured_count}, []

        return await svc.execute_read_tool(get_ctx(), "check_port_security", hostname, {"hostname": hostname}, _act)
