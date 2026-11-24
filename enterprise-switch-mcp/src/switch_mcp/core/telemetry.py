"""OpenTelemetry tracing and Prometheus metrics instrumentation."""

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram

from switch_mcp.core.config import Settings

MCP_TOOL_CALLS_TOTAL = Counter(
    "switch_mcp_tool_calls_total",
    "Total number of MCP tool invocations",
    ["tool_name", "role", "status", "risk_level"],
)

MCP_TOOL_DURATION_SECONDS = Histogram(
    "switch_mcp_tool_duration_seconds",
    "Duration of MCP tool execution in seconds",
    ["tool_name", "vendor"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0, 30.0, 60.0),
)

GUARDRAIL_BLOCKS_TOTAL = Counter(
    "switch_mcp_guardrail_blocks_total",
    "Total destructive AI actions intercepted by Safe Guardrails",
    ["tool_name", "rule_id"],
)

APPROVAL_REQUESTS_TOTAL = Counter(
    "switch_mcp_approval_requests_total",
    "Change requests created and transitioned",
    ["risk_level", "state"],
)

ACTIVE_SSH_SESSIONS = Gauge(
    "switch_mcp_active_ssh_sessions",
    "Current active SSH sessions to Cisco/Aruba switches",
    ["vendor"],
)


def configure_telemetry(settings: Settings) -> trace.Tracer:
    """Initialize OpenTelemetry TracerProvider with OTLP gRPC exporter."""
    resource = Resource.create({"service.name": settings.otel_service_name, "env": settings.app_env})
    provider = TracerProvider(resource=resource)
    if settings.otel_exporter_otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return trace.get_tracer("switch_mcp")
