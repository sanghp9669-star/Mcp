"""Structured JSON logging with secret redaction for ELK / OpenSearch."""

import logging
import re
import sys
from typing import Any

import structlog

_SECRET_PATTERNS = [
    re.compile(r"(password|secret|token|enable_secret|snmp_community)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"(secret|key|auth|priv)\s+cipher\s+\S+", re.IGNORECASE),
]


def _redact_secrets(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Scrub sensitive tokens and switch secrets before emitting logs."""
    sensitive_keys = {"password", "secret", "enable_secret", "token", "mfa_code", "private_key"}
    for key in list(event_dict.keys()):
        if key.lower() in sensitive_keys:
            event_dict[key] = "***REDACTED***"
        elif isinstance(event_dict[key], str):
            val = event_dict[key]
            for pat in _SECRET_PATTERNS:
                val = pat.sub("***REDACTED***", val)
            event_dict[key] = val
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog JSON renderer for container/OpenSearch ingestion."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            _redact_secrets,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    return structlog.get_logger(name)
