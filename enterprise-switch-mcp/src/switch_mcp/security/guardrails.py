"""AI Safe Guardrails & CLI Sanitization Engine.

Blocks destructive operations from direct AI execution and forces:
1. Change Plan generation
2. Risk Analysis
3. Approval Requirement
4. Safe CLI Command preview (never executed directly)
"""

import ipaddress
import re
from dataclasses import dataclass

from switch_mcp.core.exceptions import GuardrailViolationError, ValidationError
from switch_mcp.core.telemetry import GUARDRAIL_BLOCKS_TOTAL

FORBIDDEN_COMMAND_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("GR-001", re.compile(r"\breload\b", re.IGNORECASE), "Device reboot / reload is prohibited via direct AI execution."),
    ("GR-002", re.compile(r"\berase\s+startup-config\b", re.IGNORECASE), "Erasing startup-config destroys persistent boot configuration."),
    ("GR-003", re.compile(r"\bwrite\s+erase\b", re.IGNORECASE), "write erase wipes NVRAM startup configuration."),
    ("GR-004", re.compile(r"\bfactory[\s-]+reset\b|\berase\s+all\b", re.IGNORECASE), "Factory reset wipes all switch configuration and keys."),
    ("GR-005", re.compile(r"\bformat\s+flash", re.IGNORECASE), "Formatting flash destroys OS image and crashinfo."),
    ("GR-006", re.compile(r"\bdelete\s+(/force\s+)?(/recursive\s+)?flash", re.IGNORECASE), "Deleting flash files may brick the switch."),
    ("GR-007", re.compile(r"\bdelete\s+(/force\s+)?(flash:)?vlan\.dat\b", re.IGNORECASE), "Deleting vlan.dat wipes VTP/VLAN database."),
    ("GR-008", re.compile(r"\bxmodem\b", re.IGNORECASE), "XMODEM recovery cannot be executed over remote MCP SSH."),
    ("GR-009", re.compile(r"\bconfreg\s+0x2142\b|\bno\s+service\s+password-recovery\b|\bpassword[\s-]+recovery\b", re.IGNORECASE), "Password recovery operations require physical console access."),
]

_SAFE_INTERFACE_RE = re.compile(r"^[A-Za-z0-9/\-.:]{1,48}$")
_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_.]{1,126}[A-Za-z0-9]$")
_SAFE_VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,32}$")
_SAFE_DESCRIPTION_RE = re.compile(r"^[A-Za-z0-9 _\-.,:/()]{1,100}$")
_SHELL_INJECTION_RE = re.compile(r"[\r\n\x00;|&$`><]")


@dataclass(frozen=True, slots=True)
class GuardrailChangePlan:
    rule_id: str
    reason: str
    risk_level: str
    approval_requirement: str
    change_plan_steps: list[str]
    suggested_cli_commands: list[str]


class AISafeGuardrails:
    """Validates commands and inputs against destructive ops and injection attacks."""

    @staticmethod
    def inspect_commands(tool_name: str, commands: list[str] | str, vendor: str = "cisco_ios") -> None:
        """Raise GuardrailViolationError with Change Plan if any forbidden pattern matches."""
        cmd_list = [commands] if isinstance(commands, str) else commands
        joined = "\n".join(cmd_list)

        for rule_id, pattern, reason in FORBIDDEN_COMMAND_PATTERNS:
            if pattern.search(joined):
                GUARDRAIL_BLOCKS_TOTAL.labels(tool_name=tool_name, rule_id=rule_id).inc()
                plan = AISafeGuardrails.build_blocked_change_plan(
                    rule_id=rule_id,
                    reason=reason,
                    commands=cmd_list,
                    vendor=vendor,
                )
                raise GuardrailViolationError(
                    f"AI Safe Guardrail {rule_id}: {reason} Direct execution blocked.",
                    details={
                        "rule_id": plan.rule_id,
                        "risk": plan.risk_level,
                        "approval_requirement": plan.approval_requirement,
                        "change_plan": plan.change_plan_steps,
                        "cli_commands": plan.suggested_cli_commands,
                        "executed": False,
                    },
                )

    @staticmethod
    def build_blocked_change_plan(
        rule_id: str,
        reason: str,
        commands: list[str],
        vendor: str,
    ) -> GuardrailChangePlan:
        return GuardrailChangePlan(
            rule_id=rule_id,
            reason=reason,
            risk_level="CRITICAL",
            approval_requirement="SuperAdmin + Hardware MFA TOTP + Approved Change Ticket (CAB)",
            change_plan_steps=[
                "1. Backup running-config and startup-config to immutable Vault/DB store.",
                "2. Verify out-of-band console / secondary uplink redundancy before maintenance window.",
                "3. Open Change Ticket and obtain SuperAdmin + MFA approval.",
                "4. Execute generated CLI commands manually via bastion/console during approved window.",
                "5. Verify post-change reachability, spanning-tree convergence, and stack health.",
            ],
            suggested_cli_commands=[
                f"! Target Vendor: {vendor} (MANUAL EXECUTION ONLY AFTER CAB APPROVAL)",
                *[cmd.strip() for cmd in commands if cmd.strip()],
            ],
        )

    @staticmethod
    def sanitize_hostname(hostname: str) -> str:
        val = hostname.strip()
        if _SHELL_INJECTION_RE.search(val) or not _SAFE_HOSTNAME_RE.match(val):
            raise ValidationError(f"Invalid switch hostname: {hostname!r}")
        return val

    @staticmethod
    def sanitize_mgmt_ip(mgmt_ip: str) -> str:
        raw = mgmt_ip.strip()
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValidationError(f"Invalid management IP address: {mgmt_ip!r}") from exc
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise ValidationError(f"Disallowed management IP range (loopback/link-local/multicast): {mgmt_ip!r}")
        return str(addr)

    @staticmethod
    def sanitize_ssh_port(port: int) -> int:
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValidationError(f"SSH port must be between 1 and 65535, got {port!r}")
        return port

    @staticmethod
    def sanitize_interface(interface: str) -> str:
        val = interface.strip()
        if _SHELL_INJECTION_RE.search(val) or not _SAFE_INTERFACE_RE.match(val):
            raise ValidationError(f"Invalid interface identifier: {interface!r}")
        return val

    @staticmethod
    def sanitize_vlan_id(vlan_id: int) -> int:
        if not isinstance(vlan_id, int) or vlan_id < 1 or vlan_id > 4094:
            raise ValidationError(f"VLAN ID must be between 1 and 4094, got {vlan_id!r}")
        if vlan_id in (1, 1002, 1003, 1004, 1005):
            raise ValidationError(f"Modifying or deleting reserved default VLAN {vlan_id} is prohibited")
        return vlan_id

    @staticmethod
    def sanitize_vlan_name(name: str) -> str:
        val = name.strip()
        if _SHELL_INJECTION_RE.search(val) or not _SAFE_VLAN_NAME_RE.match(val):
            raise ValidationError("VLAN name must be 1-32 chars [A-Za-z0-9_-.]")
        return val

    @staticmethod
    def sanitize_description(description: str) -> str:
        val = description.strip()
        if _SHELL_INJECTION_RE.search(val) or not _SAFE_DESCRIPTION_RE.match(val):
            raise ValidationError("Interface description contains disallowed characters or exceeds 100 chars")
        return val

    @staticmethod
    def sanitize_allowed_vlans(vlans: str) -> str:
        val = vlans.strip()
        if not re.match(r"^[0-9,\-]+$", val):
            raise ValidationError("Allowed VLAN list must only contain digits, commas, and hyphens (e.g. '10,20,30-40')")
        return val
