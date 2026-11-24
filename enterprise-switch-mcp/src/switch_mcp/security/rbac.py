"""5-Role RBAC Matrix and Authorization Engine for all MCP Tools & Resources."""

from enum import StrEnum

from switch_mcp.core.exceptions import AuthorizationError
from switch_mcp.security.auth import RequestContext


class Role(StrEnum):
    SUPER_ADMIN = "SuperAdmin"
    NETWORK_ADMIN = "NetworkAdmin"
    NOC = "NOC"
    AUDITOR = "Auditor"
    GUEST = "Guest"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Complete permission matrix covering every single MCP Tool (46 tools) and Resource (9 resources)
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.SUPER_ADMIN: frozenset({"*"}),
    Role.NETWORK_ADMIN: frozenset({
        # Device Tools
        "list_devices", "add_device", "remove_device", "test_ssh_connection",
        "get_device_info", "get_running_config", "get_startup_config",
        "get_interfaces", "get_neighbors", "get_mac_table", "get_arp_table", "get_logs",
        # VLAN Tools
        "get_vlans", "create_vlan", "delete_vlan", "rename_vlan",
        # Port Tools
        "get_ports", "shutdown_port", "no_shutdown_port", "set_access_vlan",
        "set_trunk", "set_description", "enable_port_security", "disable_port_security",
        # Backup Tools
        "backup_running_config", "backup_startup_config", "restore_config", "compare_configs",
        # Troubleshooting Tools
        "interface_errors", "identify_loop", "check_uplink", "cable_diagnostics",
        "spanning_tree_check", "mac_flapping_detection",
        # Security Tools
        "audit_security", "find_unused_ports", "find_vlan_mismatch",
        "detect_native_vlan_mismatch", "check_telnet_enabled",
        "check_snmp_security", "check_port_security",
        # Inventory & Health Tools
        "collect_inventory", "collect_serials", "collect_software_versions", "collect_uptime",
        "cpu_health", "memory_health", "temperature_health", "stack_health",
        # Approval Tools (create + approve MEDIUM/HIGH, cannot approve CRITICAL)
        "create_change_request", "approve_change", "reject_change", "view_pending_changes",
        # Resources
        "resource:devices", "resource:inventory", "resource:vlans", "resource:configs",
        "resource:backups", "resource:health", "resource:topology", "resource:approvals",
    }),
    Role.NOC: frozenset({
        # Read-only Device & Troubleshooting
        "list_devices", "test_ssh_connection", "get_device_info", "get_interfaces", "get_neighbors",
        "get_mac_table", "get_arp_table", "get_logs", "get_vlans", "get_ports",
        "compare_configs",
        "interface_errors", "identify_loop", "check_uplink", "cable_diagnostics",
        "spanning_tree_check", "mac_flapping_detection",
        "find_unused_ports", "find_vlan_mismatch", "detect_native_vlan_mismatch",
        "collect_inventory", "collect_serials", "collect_software_versions", "collect_uptime",
        "cpu_health", "memory_health", "temperature_health", "stack_health",
        "create_change_request", "view_pending_changes",
        # Resources
        "resource:devices", "resource:inventory", "resource:vlans",
        "resource:health", "resource:topology", "resource:approvals",
    }),
    Role.AUDITOR: frozenset({
        # Config Read, Security Audit & Audit Logs
        "list_devices", "get_device_info", "get_running_config", "get_startup_config",
        "get_logs", "get_vlans", "compare_configs",
        "audit_security", "find_unused_ports", "find_vlan_mismatch",
        "detect_native_vlan_mismatch", "check_telnet_enabled",
        "check_snmp_security", "check_port_security",
        "collect_inventory", "collect_serials", "collect_software_versions", "collect_uptime",
        "view_pending_changes",
        # Resources
        "resource:devices", "resource:inventory", "resource:configs",
        "resource:backups", "resource:auditlogs", "resource:approvals",
    }),
    Role.GUEST: frozenset({
        # Limited Read Only (no configs, no logs, no security scans)
        "list_devices", "get_device_info", "get_vlans", "get_neighbors",
        "cpu_health", "memory_health", "temperature_health", "stack_health",
        "resource:devices", "resource:health", "resource:topology",
    }),
}

# Risk classification per MCP Tool
TOOL_RISK_MATRIX: dict[str, RiskLevel] = {
    # LOW (Auto-execute, read-only or non-disruptive backup)
    "list_devices": RiskLevel.LOW,
    "add_device": RiskLevel.LOW,
    "test_ssh_connection": RiskLevel.LOW,
    "get_device_info": RiskLevel.LOW,
    "get_running_config": RiskLevel.LOW,
    "get_startup_config": RiskLevel.LOW,
    "get_interfaces": RiskLevel.LOW,
    "get_neighbors": RiskLevel.LOW,
    "get_mac_table": RiskLevel.LOW,
    "get_arp_table": RiskLevel.LOW,
    "get_logs": RiskLevel.LOW,
    "get_vlans": RiskLevel.LOW,
    "get_ports": RiskLevel.LOW,
    "backup_running_config": RiskLevel.LOW,
    "backup_startup_config": RiskLevel.LOW,
    "compare_configs": RiskLevel.LOW,
    "interface_errors": RiskLevel.LOW,
    "identify_loop": RiskLevel.LOW,
    "check_uplink": RiskLevel.LOW,
    "cable_diagnostics": RiskLevel.LOW,
    "spanning_tree_check": RiskLevel.LOW,
    "mac_flapping_detection": RiskLevel.LOW,
    "audit_security": RiskLevel.LOW,
    "find_unused_ports": RiskLevel.LOW,
    "find_vlan_mismatch": RiskLevel.LOW,
    "detect_native_vlan_mismatch": RiskLevel.LOW,
    "check_telnet_enabled": RiskLevel.LOW,
    "check_snmp_security": RiskLevel.LOW,
    "check_port_security": RiskLevel.LOW,
    "collect_inventory": RiskLevel.LOW,
    "collect_serials": RiskLevel.LOW,
    "collect_software_versions": RiskLevel.LOW,
    "collect_uptime": RiskLevel.LOW,
    "cpu_health": RiskLevel.LOW,
    "memory_health": RiskLevel.LOW,
    "temperature_health": RiskLevel.LOW,
    "stack_health": RiskLevel.LOW,
    "view_pending_changes": RiskLevel.LOW,
    "create_change_request": RiskLevel.LOW,
    "approve_change": RiskLevel.LOW,
    "reject_change": RiskLevel.LOW,
    # MEDIUM (Requires 1 approver)
    "create_vlan": RiskLevel.MEDIUM,
    "rename_vlan": RiskLevel.MEDIUM,
    "set_description": RiskLevel.MEDIUM,
    "set_access_vlan": RiskLevel.MEDIUM,
    "no_shutdown_port": RiskLevel.MEDIUM,
    "enable_port_security": RiskLevel.MEDIUM,
    # HIGH (Requires 2 distinct approvers)
    "shutdown_port": RiskLevel.HIGH,
    "set_trunk": RiskLevel.HIGH,
    "disable_port_security": RiskLevel.HIGH,
    "delete_vlan": RiskLevel.HIGH,
    "remove_device": RiskLevel.HIGH,
    # CRITICAL (Requires SuperAdmin + MFA + Change Ticket)
    "restore_config": RiskLevel.CRITICAL,
}


class RBACEnforcer:
    """Evaluates Least Privilege RBAC checks for MCP tools and resources."""

    @staticmethod
    def resolve_role(role_name: str) -> Role:
        try:
            return Role(role_name)
        except ValueError as exc:
            raise AuthorizationError(f"Unknown RBAC role: {role_name}") from exc

    @classmethod
    def check_permission(cls, ctx: RequestContext, permission: str) -> None:
        role = cls.resolve_role(ctx.role)
        allowed = ROLE_PERMISSIONS[role]
        if "*" in allowed or permission in allowed:
            return
        raise AuthorizationError(
            f"Role '{role.value}' is not authorized to invoke '{permission}'",
            details={"role": role.value, "permission": permission, "user": ctx.username},
        )

    @classmethod
    def get_tool_risk(cls, tool_name: str) -> RiskLevel:
        return TOOL_RISK_MATRIX.get(tool_name, RiskLevel.HIGH)
