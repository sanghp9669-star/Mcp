"""Canonical Pydantic schemas for MCP Tool responses and request inputs."""

from typing import Any

from pydantic import BaseModel, Field


class MCPToolResponse(BaseModel):
    """Standard AI Response Envelope required across all MCP Tools."""

    status: str = Field(..., description="success | error | pending_approval | blocked")
    hostname: str = Field(..., description="Target switch hostname or GLOBAL")
    summary: str = Field(..., description="Human and AI readable execution summary")
    risk: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    recommendations: list[str] = Field(default_factory=list)
    audit_id: str = Field(..., description="Immutable audit trail ID (AUD-...)")
    data: Any = None
    approval_id: str | None = None
