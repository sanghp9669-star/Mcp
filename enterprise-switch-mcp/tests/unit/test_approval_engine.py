"""Unit tests for ApprovalEngine risk policies and TOTP verification."""

import pyotp

from switch_mcp.security.auth import AuthService
from switch_mcp.security.rbac import RiskLevel
from switch_mcp.services.approval_service import ApprovalEngine


def test_risk_policies() -> None:
    low = ApprovalEngine.assess_policy(RiskLevel.LOW)
    med = ApprovalEngine.assess_policy(RiskLevel.MEDIUM)
    high = ApprovalEngine.assess_policy(RiskLevel.HIGH)
    crit = ApprovalEngine.assess_policy(RiskLevel.CRITICAL)

    assert low.required_approvals == 0
    assert med.required_approvals == 1
    assert high.required_approvals == 2
    assert crit.requires_superadmin is True
    assert crit.requires_mfa is True
    assert crit.requires_change_ticket is True


def test_totp_verification() -> None:
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    assert AuthService.verify_totp(secret, code) is True
    assert AuthService.verify_totp(secret, "000000") is False
