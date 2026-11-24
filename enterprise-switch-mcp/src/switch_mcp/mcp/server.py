"""FastMCP server assembly registering all 9 resources and 46 enterprise tools."""

from contextvars import ContextVar

from fastmcp import FastMCP

from switch_mcp.core.exceptions import AuthenticationError
from switch_mcp.mcp.resources import register_resources
from switch_mcp.mcp.tools_approval import register_approval_tools
from switch_mcp.mcp.tools_backup import register_backup_tools
from switch_mcp.mcp.tools_device import register_device_tools
from switch_mcp.mcp.tools_health import register_health_tools
from switch_mcp.mcp.tools_inventory import register_inventory_tools
from switch_mcp.mcp.tools_port import register_port_tools
from switch_mcp.mcp.tools_security import register_security_tools
from switch_mcp.mcp.tools_troubleshoot import register_troubleshoot_tools
from switch_mcp.mcp.tools_vlan import register_vlan_tools
from switch_mcp.security.auth import RequestContext
from switch_mcp.services.network_service import NetworkService

current_request_ctx: ContextVar[RequestContext | None] = ContextVar(
    "current_request_ctx", default=None
)


def require_request_context() -> RequestContext:
    ctx = current_request_ctx.get()
    if ctx is None:
        raise AuthenticationError("Unauthenticated MCP invocation: missing RequestContext")
    return ctx


def build_mcp_server(network_service: NetworkService) -> FastMCP:
    """Create and configure the FastMCP server with all tools and resources."""
    mcp = FastMCP(
        name="enterprise-switch-mcp",
        instructions=(
            "Enterprise Network Automation MCP Server for Cisco Catalyst (3750CX, 2960, 2960S, 2960X) "
            "and ArubaOS-Switch (2930F, 2930M). All mutations enforce Zero-Trust RBAC, AI Safe Guardrails, "
            "Approval Workflows, and Immutable Audit Logging."
        ),
    )

    register_resources(mcp, network_service, require_request_context)
    register_device_tools(mcp, network_service, require_request_context)
    register_vlan_tools(mcp, network_service, require_request_context)
    register_port_tools(mcp, network_service, require_request_context)
    register_backup_tools(mcp, network_service, require_request_context)
    register_troubleshoot_tools(mcp, network_service, require_request_context)
    register_security_tools(mcp, network_service, require_request_context)
    register_inventory_tools(mcp, network_service, require_request_context)
    register_health_tools(mcp, network_service, require_request_context)
    register_approval_tools(mcp, network_service, require_request_context)

    return mcp
