"""OAuth2 / OIDC JWT authentication, MFA verification, and RequestContext."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import jwt
import pyotp
from jwt import PyJWKClient

from switch_mcp.core.config import Settings
from switch_mcp.core.exceptions import AuthenticationError


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Immutable authenticated caller context propagated across all layers."""

    user_id: str
    username: str
    email: str
    role: str
    ai_agent: str
    source_ip: str
    token_jti: str
    mfa_verified: bool = False
    mfa_secret: str | None = None
    scopes: tuple[str, ...] = field(default_factory=tuple)
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AuthService:
    """Validates OAuth2/OIDC JWT bearer tokens and TOTP MFA codes."""

    def __init__(self, settings: Settings, redis_client: Any | None = None) -> None:
        self._settings = settings
        self._redis = redis_client
        self._jwk_client: PyJWKClient | None = (
            PyJWKClient(settings.oidc_jwks_url, cache_keys=True)
            if settings.oidc_jwks_url and settings.jwt_algorithm == "RS256"
            else None
        )

    async def authenticate_token(
        self,
        bearer_token: str,
        ai_agent: str = "unknown-agent",
        source_ip: str = "127.0.0.1",
    ) -> RequestContext:
        """Verify JWT signature, claims, expiration, and revocation list."""
        if not bearer_token:
            raise AuthenticationError("Missing bearer token")

        token = bearer_token.removeprefix("Bearer ").strip()
        try:
            if self._settings.jwt_algorithm == "RS256":
                if not self._jwk_client:
                    raise AuthenticationError("OIDC JWKS URL not configured for RS256")
                signing_key = self._jwk_client.get_signing_key_from_jwt(token).key
            else:
                if not self._settings.jwt_secret_key:
                    raise AuthenticationError("JWT secret key not configured for HS256")
                signing_key = self._settings.jwt_secret_key.get_secret_value()

            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[self._settings.jwt_algorithm],
                audience=self._settings.jwt_audience,
                issuer=self._settings.jwt_issuer,
                options={"require": ["sub", "exp", "iat", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"Invalid or expired JWT: {exc}") from exc

        jti = str(payload["jti"])
        if self._redis is not None and await self._redis.is_token_revoked(jti):
            raise AuthenticationError("Token has been revoked")

        role = str(payload.get("role", "Guest"))
        scopes = tuple(str(s) for s in payload.get("scope", "").split() if s)
        return RequestContext(
            user_id=str(payload["sub"]),
            username=str(payload.get("preferred_username", payload["sub"])),
            email=str(payload.get("email", "")),
            role=role,
            ai_agent=ai_agent or str(payload.get("azp", "mcp-client")),
            source_ip=source_ip,
            token_jti=jti,
            mfa_verified=bool(payload.get("amr") and "mfa" in payload.get("amr", [])),
            scopes=scopes,
        )

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        """Verify a 6-digit RFC 6238 TOTP code with a 1-step drift window."""
        if not secret or not otp_code or not otp_code.isdigit() or len(otp_code) != 6:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code, valid_window=1)
