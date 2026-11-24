"""Security regression tests verifying OWASP & AI Safe Guardrail enforcement."""

import pytest

from switch_mcp.core.exceptions import AuthenticationError, ValidationError
from switch_mcp.core.config import Settings
from switch_mcp.security.auth import AuthService
from switch_mcp.security.guardrails import AISafeGuardrails


@pytest.mark.asyncio
async def test_expired_or_tampered_jwt_rejected() -> None:
    settings = Settings(
        jwt_algorithm="HS256",
        jwt_issuer="https://sso.test.local",
        jwt_audience="enterprise-switch-mcp",
        jwt_secret_key="super-secret-signing-key-32-chars!!",
    )
    auth = AuthService(settings)
    with pytest.raises(AuthenticationError):
        await auth.authenticate_token("Bearer invalid.jwt.token")


@pytest.mark.parametrize(
    "malicious_desc",
    [
        "uplink; reload",
        "port1 | write erase",
        "line1\nno shutdown",
        "bad`whoami`desc",
    ],
)
def test_cli_command_injection_blocked(malicious_desc: str) -> None:
    with pytest.raises(ValidationError):
        AISafeGuardrails.sanitize_description(malicious_desc)
