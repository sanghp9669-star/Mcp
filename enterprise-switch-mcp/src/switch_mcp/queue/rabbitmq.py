"""RabbitMQ async event bus for audit log shipping and async backup/approval jobs."""

import json
from typing import Any

import aio_pika

from switch_mcp.core.config import Settings
from switch_mcp.core.logging import get_logger

_log = get_logger(__name__)


class RabbitMQBus:
    """Durable topic-exchange publisher for enterprise network events."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._connection: aio_pika.abc.AbstractRobustConnection | None = None
        self._channel: aio_pika.abc.AbstractChannel | None = None
        self._exchange: aio_pika.abc.AbstractExchange | None = None

    async def connect(self) -> None:
        if self._connection and not self._connection.is_closed:
            return
        self._connection = await aio_pika.connect_robust(
            self._settings.rabbitmq_url.get_secret_value()
        )
        self._channel = await self._connection.channel()
        self._exchange = await self._channel.declare_exchange(
            self._settings.rabbitmq_exchange,
            aio_pika.ExchangeType.TOPIC,
            durable=True,
        )

    async def publish_event(self, routing_key: str, payload: dict[str, Any]) -> None:
        try:
            await self.connect()
            assert self._exchange is not None
            msg = aio_pika.Message(
                body=json.dumps(payload, default=str).encode("utf-8"),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json",
            )
            await self._exchange.publish(msg, routing_key=routing_key)
        except Exception as exc:
            _log.warning("rabbitmq_publish_failed", routing_key=routing_key, error=str(exc))

    async def health_check(self) -> bool:
        try:
            await self.connect()
            return self._connection is not None and not self._connection.is_closed
        except Exception:
            return False

    async def close(self) -> None:
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
