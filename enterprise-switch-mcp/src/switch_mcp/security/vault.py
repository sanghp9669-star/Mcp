"""HashiCorp Vault integration for switch credentials and config encryption."""

import asyncio
from dataclasses import dataclass

import hvac

from switch_mcp.core.config import Settings
from switch_mcp.core.exceptions import VaultSecretError


@dataclass(frozen=True, slots=True)
class SwitchCredentials:
    username: str
    password: str
    enable_secret: str | None = None
    ssh_private_key: str | None = None


class VaultClient:
    """Async wrapper over hvac for KV v2 switch credential retrieval."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: hvac.Client | None = None

    def _connect_sync(self) -> hvac.Client:
        if self._client and self._client.is_authenticated():
            return self._client

        client = hvac.Client(url=self._settings.vault_addr)
        if self._settings.vault_auth_method == "approle":
            if not self._settings.vault_role_id or not self._settings.vault_secret_id:
                raise VaultSecretError("Vault AppRole credentials are not configured")
            client.auth.approle.login(
                role_id=self._settings.vault_role_id,
                secret_id=self._settings.vault_secret_id.get_secret_value(),
            )
        else:
            if not self._settings.vault_token:
                raise VaultSecretError("Vault token is not configured")
            client.token = self._settings.vault_token.get_secret_value()

        if not client.is_authenticated():
            raise VaultSecretError("Failed to authenticate with HashiCorp Vault")
        self._client = client
        return client

    async def get_switch_credentials(self, vault_path: str) -> SwitchCredentials:
        """Fetch switch SSH username, password, and enable secret from Vault KV v2."""
        def _read() -> dict:
            client = self._connect_sync()
            resp = client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                mount_point=self._settings.vault_mount_kv,
            )
            return resp["data"]["data"]

        try:
            data = await asyncio.to_thread(_read)
            return SwitchCredentials(
                username=str(data["username"]),
                password=str(data["password"]),
                enable_secret=data.get("enable_secret"),
                ssh_private_key=data.get("ssh_private_key"),
            )
        except Exception as exc:
            raise VaultSecretError(
                f"Unable to retrieve switch credentials at '{vault_path}': {exc}"
            ) from exc

    async def store_switch_credentials(
        self,
        vault_path: str,
        creds: SwitchCredentials,
    ) -> None:
        """Store switch SSH credentials securely in Vault KV v2 (never in PostgreSQL)."""
        def _write() -> None:
            client = self._connect_sync()
            secret_payload = {
                "username": creds.username,
                "password": creds.password,
            }
            if creds.enable_secret:
                secret_payload["enable_secret"] = creds.enable_secret
            if creds.ssh_private_key:
                secret_payload["ssh_private_key"] = creds.ssh_private_key
            client.secrets.kv.v2.create_or_update_secret(
                path=vault_path,
                secret=secret_payload,
                mount_point=self._settings.vault_mount_kv,
            )

        try:
            await asyncio.to_thread(_write)
        except Exception as exc:
            raise VaultSecretError(
                f"Unable to store switch credentials at '{vault_path}': {exc}"
            ) from exc

    async def delete_switch_credentials(self, vault_path: str) -> None:
        """Delete switch SSH credentials metadata and versions from Vault KV v2."""
        def _delete() -> None:
            client = self._connect_sync()
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=vault_path,
                mount_point=self._settings.vault_mount_kv,
            )

        try:
            await asyncio.to_thread(_delete)
        except Exception as exc:
            raise VaultSecretError(
                f"Unable to delete switch credentials at '{vault_path}': {exc}"
            ) from exc

    async def health_check(self) -> bool:
        def _health() -> bool:
            client = hvac.Client(url=self._settings.vault_addr)
            status = client.sys.read_health_status(method="GET")
            return bool(status)

        try:
            return await asyncio.to_thread(_health)
        except Exception:
            return False
