"""Normalized log event schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    """Normalized representation of a single security log entry."""

    timestamp: datetime
    host: str = "unknown"
    source: str = "syslog"
    process: str = "unknown"
    pid: int | None = None
    event_type: str = "syslog_generic"
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    command: str | None = None
    outcome: str = "unknown"
    raw: str
    metadata: dict[str, Any] = Field(default_factory=dict)
