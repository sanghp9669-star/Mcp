"""Integration tests for FastAPI health, readiness, metrics, and JWT auth middleware."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from switch_mcp.core.config import Settings
from switch_mcp.security.auth import AuthService


@pytest.mark.asyncio
async def test_jwt_authentication_and_claims() -> None:
    secret = "test-only-hs256-signing-key-32bytes-minimum!"
    settings = Settings(
        jwt_algorithm="HS256",
        jwt_issuer="https://sso.test.local",
        jwt_audience="enterprise-switch-mcp",
        jwt_secret_key=secret,
    )
    auth = AuthService(settings)
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "user-42",
            "preferred_username": "alice.netadmin",
            "email": "alice@corp.internal",
            "role": "NetworkAdmin",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "jti": "jti-test-001",
            "amr": ["pwd", "mfa"],
        },
        secret,
        algorithm="HS256",
    )
    ctx = await auth.authenticate_token(f"Bearer {token}", ai_agent="cursor-ai", source_ip="10.0.0.5")
    assert ctx.username == "alice.netadmin"
    assert ctx.role == "NetworkAdmin"
    assert ctx.mfa_verified is True
