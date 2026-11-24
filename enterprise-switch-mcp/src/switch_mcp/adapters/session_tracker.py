"""Real-time SSH session state tracker and WebSocket/pub-sub event broadcaster."""

import asyncio
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable


@dataclass
class SSHSessionRecord:
    session_id: str
    hostname: str
    mgmt_ip: str
    ssh_port: int
    vendor: str
    model: str
    status: str  # connecting | connected | executing | disconnecting | closed | error
    current_command: str | None
    started_at: str
    started_monotonic: float
    command_started_at: str | None = None
    command_started_monotonic: float | None = None
    finished_at: str | None = None
    last_error: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        now_m = time.monotonic()
        elapsed_ms = int((now_m - self.started_monotonic) * 1000) if self.finished_at is None else None
        cmd_elapsed_ms = (
            int((now_m - self.command_started_monotonic) * 1000)
            if (self.command_started_monotonic is not None and self.finished_at is None)
            else None
        )
        data = asdict(self)
        data.pop("started_monotonic", None)
        data.pop("command_started_monotonic", None)
        data["elapsed_ms"] = elapsed_ms
        data["command_elapsed_ms"] = cmd_elapsed_ms
        return data


EventListener = Callable[[dict[str, Any]], Awaitable[None]]


class SSHSessionTracker:
    """Server-authoritative tracker for active Cisco & Aruba SSH sessions."""

    def __init__(self, max_recent_closed: int = 25) -> None:
        self._sessions: dict[str, SSHSessionRecord] = {}
        self._recent_closed: list[dict[str, Any]] = []
        self._max_recent_closed = max_recent_closed
        self._listeners: set[EventListener] = set()
        self._lock = asyncio.Lock()

    def subscribe(self, listener: EventListener) -> None:
        self._listeners.add(listener)

    def unsubscribe(self, listener: EventListener) -> None:
        self._listeners.discard(listener)

    async def _broadcast(self, event_type: str, session_payload: dict[str, Any]) -> None:
        event = {"type": event_type, "session": session_payload}
        for listener in list(self._listeners):
            try:
                await listener(event)
            except Exception:
                self._listeners.discard(listener)

    async def start_session(
        self,
        *,
        hostname: str,
        mgmt_ip: str,
        ssh_port: int,
        vendor: str,
        model: str,
    ) -> str:
        session_id = f"ssh-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        now_mono = time.monotonic()
        rec = SSHSessionRecord(
            session_id=session_id,
            hostname=hostname,
            mgmt_ip=mgmt_ip,
            ssh_port=ssh_port,
            vendor=vendor,
            model=model,
            status="connecting",
            current_command="SSH handshake & enable auth",
            started_at=now_iso,
            started_monotonic=now_mono,
            command_started_at=now_iso,
            command_started_monotonic=now_mono,
        )
        async with self._lock:
            self._sessions[session_id] = rec
            payload = rec.to_public_dict()
        await self._broadcast("session:created", payload)
        return session_id

    async def mark_connected(self, session_id: str) -> None:
        async with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                return
            rec.status = "connected"
            rec.current_command = None
            rec.command_started_at = None
            rec.command_started_monotonic = None
            payload = rec.to_public_dict()
        await self._broadcast("session:updated", payload)

    async def mark_executing(self, session_id: str, command: str) -> None:
        async with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                return
            rec.status = "executing"
            rec.current_command = command
            rec.command_started_at = datetime.now(timezone.utc).isoformat()
            rec.command_started_monotonic = time.monotonic()
            payload = rec.to_public_dict()
        await self._broadcast("session:updated", payload)

    async def mark_idle(self, session_id: str) -> None:
        async with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                return
            rec.status = "connected"
            rec.current_command = None
            rec.command_started_at = None
            rec.command_started_monotonic = None
            payload = rec.to_public_dict()
        await self._broadcast("session:updated", payload)

    async def end_session(self, session_id: str, error: str | None = None) -> None:
        async with self._lock:
            rec = self._sessions.pop(session_id, None)
            if not rec:
                return
            rec.status = "error" if error else "closed"
            rec.last_error = error
            rec.finished_at = datetime.now(timezone.utc).isoformat()
            rec.current_command = None
            payload = rec.to_public_dict()
            payload["elapsed_ms"] = int((time.monotonic() - rec.started_monotonic) * 1000)
            self._recent_closed.insert(0, payload)
            self._recent_closed = self._recent_closed[: self._max_recent_closed]
        await self._broadcast("session:closed", payload)

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            active = [rec.to_public_dict() for rec in self._sessions.values()]
            recent = list(self._recent_closed)
        return {"active_sessions": active, "recent_sessions": recent}


# Singleton session tracker shared across adapters and FastAPI WebSocket routes
ssh_session_tracker = SSHSessionTracker()
