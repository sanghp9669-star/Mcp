"""Enterprise configuration powered by pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "staging", "production"] = "production"
    app_name: str = "enterprise-switch-mcp"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    mcp_transport: Literal["streamable-http", "sse", "stdio"] = "streamable-http"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Authentication & OAuth2 / JWT
    jwt_algorithm: Literal["RS256", "HS256"] = "RS256"
    jwt_issuer: str = "https://sso.enterprise.internal/realms/netops"
    jwt_audience: str = "enterprise-switch-mcp"
    oidc_jwks_url: str = ""
    jwt_secret_key: SecretStr | None = None
    mfa_issuer_name: str = "NetGuard-Switch-MCP"

    # PostgreSQL Primary & Read Replica
    postgres_dsn: SecretStr = Field(
        default=SecretStr("postgresql+asyncpg://mcp_app:postgres@localhost:5432/switch_mcp")
    )
    postgres_read_dsn: SecretStr | None = None
    postgres_pool_size: int = 20
    postgres_max_overflow: int = 10
    postgres_ssl_mode: str = "prefer"

    # Redis Sentinel / Standalone
    redis_mode: Literal["standalone", "sentinel", "cluster"] = "standalone"
    redis_sentinel_nodes: str = "localhost:26379"
    redis_sentinel_master: str = "mymaster"
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"))
    redis_password: SecretStr | None = None
    redis_lock_ttl_seconds: int = 45

    # RabbitMQ
    rabbitmq_url: SecretStr = Field(
        default=SecretStr("amqp://guest:guest@localhost:5672/")
    )
    rabbitmq_exchange: str = "switch_mcp.events"

    # HashiCorp Vault
    vault_addr: str = "http://localhost:8200"
    vault_auth_method: Literal["approle", "token"] = "approle"
    vault_role_id: str | None = None
    vault_secret_id: SecretStr | None = None
    vault_token: SecretStr | None = None
    vault_mount_kv: str = "secret"
    vault_switch_creds_prefix: str = "network/switches"

    # SSH Transport
    ssh_connect_timeout: int = 15
    ssh_command_timeout: int = 60
    ssh_known_hosts_path: str = "/etc/switch_mcp/known_hosts"
    ssh_strict_host_key_checking: bool = True
    max_concurrent_ssh_sessions: int = 50

    # Observability
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "enterprise-switch-mcp"
    prometheus_enabled: bool = True
    opensearch_url: str = ""
    opensearch_index_prefix: str = "switch-mcp-audit"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton application settings."""
    return Settings()
