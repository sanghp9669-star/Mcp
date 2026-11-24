export type RoleName = 'SuperAdmin' | 'NetworkAdmin' | 'NOC' | 'Auditor' | 'Guest';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface McpToolSpec {
  name: string;
  category:
    | 'Device'
    | 'VLAN'
    | 'Port'
    | 'Backup'
    | 'Troubleshooting'
    | 'Security'
    | 'Inventory'
    | 'Health'
    | 'Approval';
  risk: RiskLevel;
  params: string;
  description: string;
  roles: RoleName[];
}

export interface SupportedHardwareSpec {
  vendor: 'cisco' | 'aruba';
  model: string;
  osFamily: string;
  netmikoDriver: string;
  stackTechnology: string;
  stackCommand: string;
}

export const SUPPORTED_HARDWARE_MODELS: SupportedHardwareSpec[] = [
  {
    vendor: 'cisco',
    model: 'Catalyst 3750CX',
    osFamily: 'Cisco IOS',
    netmikoDriver: 'cisco_ios',
    stackTechnology: 'Standalone / StackWise (model dependent)',
    stackCommand: 'show switch',
  },
  {
    vendor: 'cisco',
    model: 'Catalyst 2960',
    osFamily: 'Cisco IOS',
    netmikoDriver: 'cisco_ios',
    stackTechnology: 'Standalone',
    stackCommand: 'show version',
  },
  {
    vendor: 'cisco',
    model: 'Catalyst 2960S',
    osFamily: 'Cisco IOS',
    netmikoDriver: 'cisco_ios',
    stackTechnology: 'Standalone & FlexStack',
    stackCommand: 'show switch',
  },
  {
    vendor: 'cisco',
    model: 'Catalyst 2960X',
    osFamily: 'Cisco IOS',
    netmikoDriver: 'cisco_ios',
    stackTechnology: 'Standalone & FlexStack-Plus',
    stackCommand: 'show switch',
  },
  {
    vendor: 'aruba',
    model: 'Aruba 2930F',
    osFamily: 'ArubaOS-Switch',
    netmikoDriver: 'hp_procurve',
    stackTechnology: 'Standalone & VSF (Virtual Switching Framework)',
    stackCommand: 'show vsf',
  },
  {
    vendor: 'aruba',
    model: 'Aruba 2930M',
    osFamily: 'ArubaOS-Switch',
    netmikoDriver: 'hp_procurve',
    stackTechnology: 'Standalone & Backplane Stacking',
    stackCommand: 'show stacking',
  },
];

const ALL_ROLES: RoleName[] = ['SuperAdmin', 'NetworkAdmin', 'NOC', 'Auditor', 'Guest'];
const OPS_READ: RoleName[] = ['SuperAdmin', 'NetworkAdmin', 'NOC', 'Auditor'];
const NET_OPS: RoleName[] = ['SuperAdmin', 'NetworkAdmin', 'NOC'];
const ADMIN_ONLY: RoleName[] = ['SuperAdmin', 'NetworkAdmin'];

export const MCP_TOOLS: McpToolSpec[] = [
  // Device (12)
  { name: 'list_devices', category: 'Device', risk: 'LOW', params: 'vendor?: str', description: 'List managed Cisco & Aruba switches from PostgreSQL inventory.', roles: ALL_ROLES },
  { name: 'add_device', category: 'Device', risk: 'LOW', params: 'hostname, mgmt_ip, vendor, model, ssh_username, ssh_password, site_code?, ssh_port?, verify_ssh?', description: 'Register switch in PostgreSQL, store SSH secrets in Vault, and verify live SSH.', roles: ADMIN_ONLY },
  { name: 'test_ssh_connection', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Verify live SSH handshake, Vault credentials, and CLI prompt readiness.', roles: NET_OPS },
  { name: 'remove_device', category: 'Device', risk: 'HIGH', params: 'hostname: str, approval_id?: str', description: 'Decommission switch from inventory and purge Vault secrets (2 approvals).', roles: ADMIN_ONLY },
  { name: 'get_device_info', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Collect hardware model, OS, serial, uptime, and stack members.', roles: ALL_ROLES },
  { name: 'get_running_config', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Fetch live running configuration from switch.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  { name: 'get_startup_config', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Fetch saved startup configuration from NVRAM/flash.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  { name: 'get_interfaces', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'List interfaces with admin/oper state, VLAN, speed, and errors.', roles: NET_OPS },
  { name: 'get_neighbors', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Discover CDP and LLDP adjacent network devices.', roles: ['SuperAdmin', 'NetworkAdmin', 'NOC', 'Guest'] },
  { name: 'get_mac_table', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Retrieve Layer 2 MAC forwarding table.', roles: NET_OPS },
  { name: 'get_arp_table', category: 'Device', risk: 'LOW', params: 'hostname: str', description: 'Retrieve Layer 3 ARP bindings.', roles: NET_OPS },
  { name: 'get_logs', category: 'Device', risk: 'LOW', params: 'hostname: str, lines?: int', description: 'Fetch recent buffered syslog messages.', roles: OPS_READ },
  // VLAN (4)
  { name: 'get_vlans', category: 'VLAN', risk: 'LOW', params: 'hostname: str', description: 'List configured VLANs and port memberships.', roles: ALL_ROLES },
  { name: 'create_vlan', category: 'VLAN', risk: 'MEDIUM', params: 'hostname, vlan_id, name, approval_id?', description: 'Create new VLAN across Cisco/Aruba (1 approval required).', roles: ADMIN_ONLY },
  { name: 'delete_vlan', category: 'VLAN', risk: 'HIGH', params: 'hostname, vlan_id, approval_id?', description: 'Remove VLAN from switch database (2 distinct approvals).', roles: ADMIN_ONLY },
  { name: 'rename_vlan', category: 'VLAN', risk: 'MEDIUM', params: 'hostname, vlan_id, new_name, approval_id?', description: 'Rename an existing VLAN (1 approval required).', roles: ADMIN_ONLY },
  // Port (8)
  { name: 'get_ports', category: 'Port', risk: 'LOW', params: 'hostname: str', description: 'Retrieve switch port state and mode summary.', roles: NET_OPS },
  { name: 'shutdown_port', category: 'Port', risk: 'HIGH', params: 'hostname, interface, approval_id?', description: 'Administratively disable switch port (2 approvals).', roles: ADMIN_ONLY },
  { name: 'no_shutdown_port', category: 'Port', risk: 'MEDIUM', params: 'hostname, interface, approval_id?', description: 'Administratively enable switch port (1 approval).', roles: ADMIN_ONLY },
  { name: 'set_access_vlan', category: 'Port', risk: 'MEDIUM', params: 'hostname, interface, vlan_id, approval_id?', description: 'Assign access/untagged VLAN on port (1 approval).', roles: ADMIN_ONLY },
  { name: 'set_trunk', category: 'Port', risk: 'HIGH', params: 'hostname, interface, native_vlan, allowed_vlans, approval_id?', description: 'Configure 802.1Q trunk / tagged VLANs (2 approvals).', roles: ADMIN_ONLY },
  { name: 'set_description', category: 'Port', risk: 'MEDIUM', params: 'hostname, interface, description, approval_id?', description: 'Update interface description label (1 approval).', roles: ADMIN_ONLY },
  { name: 'enable_port_security', category: 'Port', risk: 'MEDIUM', params: 'hostname, interface, max_macs, violation_mode, approval_id?', description: 'Enforce sticky MAC limit & violation alarm/restrict.', roles: ADMIN_ONLY },
  { name: 'disable_port_security', category: 'Port', risk: 'HIGH', params: 'hostname, interface, approval_id?', description: 'Remove port-security NAC protection (2 approvals).', roles: ADMIN_ONLY },
  // Backup (4)
  { name: 'backup_running_config', category: 'Backup', risk: 'LOW', params: 'hostname: str', description: 'Snapshot running-config to PostgreSQL with SHA-256 hash.', roles: ADMIN_ONLY },
  { name: 'backup_startup_config', category: 'Backup', risk: 'LOW', params: 'hostname: str', description: 'Snapshot startup-config to PostgreSQL with SHA-256 hash.', roles: ADMIN_ONLY },
  { name: 'restore_config', category: 'Backup', risk: 'CRITICAL', params: 'hostname, config_text, approval_id?, change_ticket?', description: 'Restore configuration (SuperAdmin + MFA + Change Ticket).', roles: ADMIN_ONLY },
  { name: 'compare_configs', category: 'Backup', risk: 'LOW', params: 'hostname: str', description: 'Unified diff between startup-config and running-config.', roles: OPS_READ },
  // Troubleshooting (6)
  { name: 'interface_errors', category: 'Troubleshooting', risk: 'LOW', params: 'hostname: str', description: 'Detect ports with input, output, or CRC frame errors.', roles: NET_OPS },
  { name: 'identify_loop', category: 'Troubleshooting', risk: 'LOW', params: 'hostname: str', description: 'Correlate STP TCNs, MAC flaps, and err-disable logs.', roles: NET_OPS },
  { name: 'check_uplink', category: 'Troubleshooting', risk: 'LOW', params: 'hostname: str', description: 'Verify uplink port status and neighbor reachability.', roles: NET_OPS },
  { name: 'cable_diagnostics', category: 'Troubleshooting', risk: 'LOW', params: 'hostname, interface', description: 'Execute TDR cable diagnostics on copper ports.', roles: NET_OPS },
  { name: 'spanning_tree_check', category: 'Troubleshooting', risk: 'LOW', params: 'hostname: str', description: 'Inspect STP/RSTP root bridge and topology changes.', roles: NET_OPS },
  { name: 'mac_flapping_detection', category: 'Troubleshooting', risk: 'LOW', params: 'hostname: str', description: 'Detect MAC addresses oscillating across multiple ports.', roles: NET_OPS },
  // Security (7)
  { name: 'audit_security', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Run CIS/Enterprise security baseline compliance audit.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  { name: 'find_unused_ports', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Locate admin-up ports with no active link.', roles: OPS_READ },
  { name: 'find_vlan_mismatch', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Identify ports assigned to undefined VLAN IDs.', roles: OPS_READ },
  { name: 'detect_native_vlan_mismatch', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Detect CDP/LLDP native VLAN mismatch & VLAN 1 trunks.', roles: OPS_READ },
  { name: 'check_telnet_enabled', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Verify cleartext Telnet is disabled on VTY/management.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  { name: 'check_snmp_security', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Verify SNMPv3 authPriv and flag v1/v2c communities.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  { name: 'check_port_security', category: 'Security', risk: 'LOW', params: 'hostname: str', description: 'Audit port-security enforcement across access ports.', roles: ['SuperAdmin', 'NetworkAdmin', 'Auditor'] },
  // Inventory (4)
  { name: 'collect_inventory', category: 'Inventory', risk: 'LOW', params: 'hostname: str', description: 'Collect chassis, stack member, and SFP module inventory.', roles: OPS_READ },
  { name: 'collect_serials', category: 'Inventory', risk: 'LOW', params: 'hostname: str', description: 'Collect chassis & stack member serial numbers.', roles: OPS_READ },
  { name: 'collect_software_versions', category: 'Inventory', risk: 'LOW', params: 'hostname: str', description: 'Collect OS versions and stack firmware parity.', roles: OPS_READ },
  { name: 'collect_uptime', category: 'Inventory', risk: 'LOW', params: 'hostname: str', description: 'Collect switch system uptime metrics.', roles: OPS_READ },
  // Health (4)
  { name: 'cpu_health', category: 'Health', risk: 'LOW', params: 'hostname: str', description: 'Inspect 5s/1m/5m CPU utilization.', roles: ALL_ROLES },
  { name: 'memory_health', category: 'Health', risk: 'LOW', params: 'hostname: str', description: 'Inspect processor DRAM utilization and free bytes.', roles: ALL_ROLES },
  { name: 'temperature_health', category: 'Health', risk: 'LOW', params: 'hostname: str', description: 'Inspect chassis thermal sensors and alarm state.', roles: ALL_ROLES },
  { name: 'stack_health', category: 'Health', risk: 'LOW', params: 'hostname: str', description: 'Inspect Cisco StackWise/FlexStack or Aruba VSF health.', roles: ALL_ROLES },
  // Approval (4)
  { name: 'create_change_request', category: 'Approval', risk: 'LOW', params: 'hostname, tool_name, cli_commands, risk_level, change_ticket?', description: 'Submit auditable Change Plan for workflow approval.', roles: NET_OPS },
  { name: 'approve_change', category: 'Approval', risk: 'LOW', params: 'request_code, mfa_code?, change_ticket?, comment?', description: 'Approve Change Request (4-eyes, SuperAdmin, MFA checks).', roles: ADMIN_ONLY },
  { name: 'reject_change', category: 'Approval', risk: 'LOW', params: 'request_code, reason', description: 'Reject Change Request with audit justification.', roles: ADMIN_ONLY },
  { name: 'view_pending_changes', category: 'Approval', risk: 'LOW', params: 'none', description: 'List pending Change Requests awaiting approval.', roles: OPS_READ },
];

export const MCP_RESOURCES = [
  { uri: 'network://devices', scope: 'All Roles', description: 'Registered Cisco & Aruba switches, management IPs, stack counts, and site mappings.' },
  { uri: 'network://inventory', scope: 'SuperAdmin, NetworkAdmin, NOC, Auditor', description: 'Hardware chassis, stack member PIDs, serial numbers, and transceiver inventory.' },
  { uri: 'network://vlans', scope: 'SuperAdmin, NetworkAdmin, NOC, Guest', description: 'Campus switching VLAN topology and synchronization status.' },
  { uri: 'network://configs', scope: 'SuperAdmin, NetworkAdmin, Auditor', description: 'Latest running/startup configuration metadata and SHA-256 checksums.' },
  { uri: 'network://backups', scope: 'SuperAdmin, NetworkAdmin, Auditor', description: 'Pre-change and scheduled configuration snapshot ledger.' },
  { uri: 'network://health', scope: 'All Roles', description: 'CPU, memory, thermal, and StackWise/VSF health telemetry history.' },
  { uri: 'network://topology', scope: 'All Roles', description: 'CDP/LLDP neighbor adjacency graph across access and distribution switches.' },
  { uri: 'network://auditlogs', scope: 'SuperAdmin, Auditor', description: 'SHA-256 hash-chained immutable audit trail of all MCP calls.' },
  { uri: 'network://approvals', scope: 'SuperAdmin, NetworkAdmin, NOC, Auditor', description: 'Pending Change Requests, risk levels, and CAB approval status.' },
];

export const GUARDRAIL_BLOCKED_PATTERNS = [
  'reload',
  'erase startup-config',
  'write erase',
  'factory reset',
  'format flash',
  'delete flash',
  'delete vlan.dat',
  'xmodem recovery',
  'password recovery',
];
