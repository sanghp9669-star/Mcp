"""FastAPI + FastMCP ASGI entrypoint with /health, /readiness, /liveness, /metrics, and JWT Auth."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from switch_mcp.adapters.session_tracker import ssh_session_tracker

from switch_mcp.cache.redis_client import RedisLayer
from switch_mcp.core.config import get_settings
from switch_mcp.core.exceptions import AuthenticationError
from switch_mcp.core.logging import configure_logging, get_logger
from switch_mcp.core.telemetry import configure_telemetry
from switch_mcp.db.repository import PostgresDatabase, SwitchRepository
from switch_mcp.mcp.server import build_mcp_server, current_request_ctx
from switch_mcp.queue.rabbitmq import RabbitMQBus
from switch_mcp.security.auth import AuthService
from switch_mcp.security.vault import VaultClient
from switch_mcp.services.approval_service import ApprovalEngine
from switch_mcp.services.audit_service import AuditEngine
from switch_mcp.services.network_service import NetworkService

settings = get_settings()
configure_logging(settings.log_level)
_log = get_logger(__name__)
configure_telemetry(settings)

db = PostgresDatabase(settings)
redis_layer = RedisLayer(settings)
rabbit_bus = RabbitMQBus(settings)
vault_client = VaultClient(settings)
repo = SwitchRepository(db)
auth_service = AuthService(settings, redis_client=redis_layer)
audit_engine = AuditEngine(repo=repo, bus=rabbit_bus)
approval_engine = ApprovalEngine(db=db)
network_service = NetworkService(
    settings=settings,
    repo=repo,
    redis=redis_layer,
    vault=vault_client,
    audit=audit_engine,
    approval=approval_engine,
)

mcp_server = build_mcp_server(network_service)
mcp_asgi_app = mcp_server.http_app(path="/mcp")


@asynccontextmanager
async def lifespan(_: FastAPI):
    _log.info("starting_switch_mcp_server", env=settings.app_env, port=settings.app_port)
    async with mcp_asgi_app.lifespan(app):
        yield
    await rabbit_bus.close()
    await redis_layer.close()
    await db.close()
    _log.info("stopped_switch_mcp_server")


app = FastAPI(
    title="Enterprise Switch MCP Server",
    version="1.0.0",
    lifespan=lifespan,
)
FastAPIInstrumentor.instrument_app(app)


@app.middleware("http")
async def jwt_auth_middleware(request: Request, call_next: Any):
    """Authenticate /mcp requests using OAuth2/JWT Bearer tokens before FastMCP execution."""
    if request.url.path in ("/health", "/liveness", "/readiness", "/metrics"):
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    ai_agent = request.headers.get("X-AI-Agent", "unknown-mcp-agent")
    source_ip = request.client.host if request.client else "127.0.0.1"

    try:
        ctx = await auth_service.authenticate_token(
            bearer_token=auth_header,
            ai_agent=ai_agent,
            source_ip=source_ip,
        )
    except AuthenticationError as exc:
        return JSONResponse(status_code=401, content={"error": exc.code, "message": exc.message})

    token_reset = current_request_ctx.set(ctx)
    try:
        return await call_next(request)
    finally:
        current_request_ctx.reset(token_reset)


@app.get("/liveness")
async def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readiness")
async def readiness() -> JSONResponse:
    pg_ok = await db.health_check()
    redis_ok = await redis_layer.health_check()
    ready = pg_ok and redis_ok
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "degraded", "postgres": pg_ok, "redis": redis_ok},
    )


@app.get("/health")
async def health() -> JSONResponse:
    pg_ok = await db.health_check()
    redis_ok = await redis_layer.health_check()
    rmq_ok = await rabbit_bus.health_check()
    vault_ok = await vault_client.health_check()
    overall = "healthy" if (pg_ok and redis_ok) else "degraded"
    return JSONResponse(
        status_code=200 if overall == "healthy" else 503,
        content={
            "status": overall,
            "dependencies": {
                "postgresql": pg_ok,
                "redis": redis_ok,
                "rabbitmq": rmq_ok,
                "vault": vault_ok,
            },
        },
    )


@app.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/ssh/sessions")
async def list_ssh_sessions() -> dict[str, Any]:
    """Return authoritative snapshot of active and recently closed SSH sessions."""
    return await ssh_session_tracker.snapshot()


@app.websocket("/ws/ssh-sessions")
async def ws_ssh_sessions(websocket: WebSocket) -> None:
    """Real-time WebSocket stream of active SSH sessions and executing CLI commands."""
    auth_header = websocket.headers.get("authorization", "")
    try:
        await auth_service.authenticate_token(
            bearer_token=auth_header,
            ai_agent="ssh-monitor-ws",
            source_ip=websocket.client.host if websocket.client else "127.0.0.1",
        )
    except AuthenticationError:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def _on_event(event: dict[str, Any]) -> None:
        await queue.put(event)

    ssh_session_tracker.subscribe(_on_event)
    try:
        snapshot = await ssh_session_tracker.snapshot()
        await websocket.send_json({"type": "init", **snapshot})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        ssh_session_tracker.unsubscribe(_on_event)


app.mount("/", mcp_asgi_app)
