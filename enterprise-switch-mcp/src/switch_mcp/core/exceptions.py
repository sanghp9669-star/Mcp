"""Typed domain and infrastructure exceptions."""

from typing import Any


class SwitchMCPError(Exception):
    """Base exception for all Switch MCP errors."""

    code: str = "INTERNAL_ERROR"
    http_status: int = 500

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(SwitchMCPError):
    code = "AUTHENTICATION_FAILED"
    http_status = 401


class AuthorizationError(SwitchMCPError):
    code = "PERMISSION_DENIED"
    http_status = 403


class GuardrailViolationError(SwitchMCPError):
    code = "GUARDRAIL_BLOCKED"
    http_status = 403


class ApprovalRequiredError(SwitchMCPError):
    code = "APPROVAL_REQUIRED"
    http_status = 202


class ValidationError(SwitchMCPError):
    code = "VALIDATION_ERROR"
    http_status = 400


class DeviceNotFoundError(SwitchMCPError):
    code = "DEVICE_NOT_FOUND"
    http_status = 404


class DeviceLockError(SwitchMCPError):
    code = "DEVICE_LOCKED"
    http_status = 409


class DeviceConnectionError(SwitchMCPError):
    code = "DEVICE_CONNECTION_FAILED"
    http_status = 502


class CommandExecutionError(SwitchMCPError):
    code = "COMMAND_EXECUTION_FAILED"
    http_status = 502


class VaultSecretError(SwitchMCPError):
    code = "VAULT_SECRET_ERROR"
    http_status = 500
