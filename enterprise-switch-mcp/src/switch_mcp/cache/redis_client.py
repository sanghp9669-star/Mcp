"""Redis Sentinel / Cluster client for distributed locking, caching, and token revocation."""

import json
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from redis.asyncio import Redis, Sentinel

from switch_mcp.core.config import Settings
from switch_mcp.core.exceptions import DeviceLockError


class RedisLayer:
    """Enterprise Redis abstraction supporting Standalone and Sentinel HA topologies."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Redis | None = None

    def connect(self) -> Redis:
        if self._client is not None:
            return self._client

        password = (
            self._settings.redis_password.get_secret_value()
            if self._settings.redis_password
            else None
        )
        if self._settings.redis_mode == "sentinel":
            nodes = [
                (host.strip(), int(port.strip()))
                for host, port in (
                    item.split(":") for item in self._settings.redis_sentinel_nodes.split(",")
                )
            ]
            sentinel = Sentinel(nodes, socket_timeout=2.0, password=password)
            self._client = sentinel.master_for(
                self._settings.redis_sentinel_master,
                decode_responses=True,
                password=password,
            )
        else:
            self._client = Redis.from_url(
                self._settings.redis_url.get_secret_value(),
                decode_responses=True,
            )
        return self._client

    @asynccontextmanager
    async def device_lock(self, hostname: str) -> AsyncIterator[None]:
        """Acquire distributed mutex lock per switch to prevent concurrent config collisions."""
        client = self.connect()
        key = f"lock:switch:{hostname}"
        token = str(uuid.uuid4())
        acquired = await client.set(key, token, nx=True, ex=self._settings.redis_lock_ttl_seconds)
        if not acquired:
            raise DeviceLockError(
                f"Switch '{hostname}' is currently locked by another active automation workflow"
            )
        try:
            yield
        finally:
            lua_release = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
            """
            await client.eval(lua_release, 1, key, token)

    async def get_cached_json(self, key: str) -> Any | None:
        raw = await self.connect().get(key)
        return json.loads(raw) if raw else None

    async def set_cached_json(self, key: str, value: Any, ttl_seconds: int = 60) -> None:
        await self.connect().set(key, json.dumps(value), ex=ttl_seconds)

    async def is_token_revoked(self, jti: str) -> bool:
        return bool(await self.connect().exists(f"revoked:jti:{jti}"))

    async def revoke_token(self, jti: str, ttl_seconds: int = 3600) -> None:
        await self.connect().set(f"revoked:jti:{jti}", "1", ex=ttl_seconds)

    async def health_check(self) -> bool:
        try:
            return bool(await self.connect().ping())
        except Exception:
            return False

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
