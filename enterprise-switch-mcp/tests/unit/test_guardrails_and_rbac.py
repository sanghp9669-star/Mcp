"""Unit tests for AI Safe Guardrails, CLI sanitization, and 5-Role RBAC."""

import pytest

from switch_mcp.core.exceptions import AuthorizationError, GuardrailViolationError, ValidationError
from switch_mcp.security.auth import RequestContext
from switch_mcp.security.guardrails import AISafeGuardrails
from switch_mcp.security.rbac import RBACEnforcer, RiskLevel


def _ctx(role: str) -> RequestContext:
    return RequestContext(
        user_id="u-001",
        username="tester",
        email="tester@corp.internal",
        role=role,
        ai_agent="claude-desktop",
        source_ip="10.10.1.5",
        token_jti="jti-123",
    )


@pytest.mark.parametrize(
    "forbidden_cmd",
    [
        "reload",
        "reload in 5",
        "erase startup-config",
        "write erase",
        "factory-reset all",
        "format flash:",
        "delete /force flash:vlan.dat",
        "delete vlan.dat",
        "copy xmodem: flash:",
        "confreg 0x2142",
    ],
)
def test_guardrail_blocks_destructive_commands(forbidden_cmd: str) -> None:
    with pytest.raises(GuardrailViolationError) as exc_info:
        AISafeGuardrails.inspect_commands("execute_config", [forbidden_cmd], vendor="cisco")
    assert exc_info.value.details["executed"] is False
    assert exc_info.value.details["risk"] == "CRITICAL"
    assert len(exc_info.value.details["change_plan"]) >= 3


def test_sanitization_blocks_command_injection() -> None:
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_interface("Gi1/0/1\nreload")
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_vlan_id(1)
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_vlan_name("BAD;VLAN")
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_mgmt_ip("169.254.169.254")
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_mgmt_ip("127.0.0.1")
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_hostname("SW-01;reload")
    assert AISafeGuardrails.sanitize_mgmt_ip("10.10.2.21") == "10.10.2.21"
    assert AISafeGuardrails.sanitize_hostname("SW-HCM-ACC-01") == "SW-HCM-ACC-01"
    assert AISafeGuardrails.sanitize_interface("GigabitEthernet1/0/24") == "GigabitEthernet1/0/24"
    assert AISafeGuardrails.sanitize_vlan_id(120) == 120


def test_rbac_matrix_least_privilege() -> None:
    # SuperAdmin has wildcard
    RBACEnforcer.check_permission(_ctx("SuperAdmin"), "restore_config")
    # NetworkAdmin can onboard switches & test SSH
    RBACEnforcer.check_permission(_ctx("NetworkAdmin"), "add_device")
    RBACEnforcer.check_permission(_ctx("NetworkAdmin"), "test_ssh_connection")
    # NOC can test SSH but cannot add or remove devices
    RBACEnforcer.check_permission(_ctx("NOC"), "test_ssh_connection")
    with pytest.raises(AuthorizationError):
        RBACEnforcer.check_permission(_ctx("NOC"), "add_device")
    # Guest cannot read configs or mutate VLANs
    RBACEnforcer.check_permission(_ctx("Guest"), "list_devices")
    with pytest.raises(AuthorizationError):
        RBACEnforcer.check_permission(_ctx("Guest"), "get_running_config")
    with pytest.raises(AuthorizationError):
        RBACEnforcer.check_permission(_ctx("NOC"), "create_vlan")
    # Auditor can read configs & audit logs, cannot shut down ports
    RBACEnforcer.check_permission(_ctx("Auditor"), "resource:auditlogs")
    with pytest.raises(AuthorizationError):
        RBACEnforcer.check_permission(_ctx("Auditor"), "shutdown_port")


def test_tool_risk_classification() -> None:
    assert RBACEnforcer.get_tool_risk("get_vlans") == RiskLevel.LOW
    assert RBACEnforcer.get_tool_risk("add_device") == RiskLevel.LOW
    assert RBACEnforcer.get_tool_risk("create_vlan") == RiskLevel.MEDIUM
    assert RBACEnforcer.get_tool_risk("shutdown_port") == RiskLevel.HIGH
    assert RBACEnforcer.get_tool_risk("remove_device") == RiskLevel.HIGH
    assert RBACEnforcer.get_tool_risk("restore_config") == RiskLevel.CRITICAL
