"""Models for detection alerts and correlated incident clusters."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity | str) -> int:
    """Return numeric sort weight for a Severity level."""
    if isinstance(severity, str):
        severity = Severity(severity.upper())
    return _SEVERITY_ORDER[severity]


class Alert(BaseModel):
    """A single rule-based or anomaly-based security alert."""

    id: str
    detector: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime
    src_ip: str | None = None
    user: str | None = None
    event_count: int = 1
    summary: str
    evidence: list[str] = Field(default_factory=list)
    features: dict[str, float] = Field(default_factory=dict)


class IncidentCluster(BaseModel):
    """Correlated group of alerts belonging to the same potential incident."""

    incident_id: str
    title: str
    severity: Severity
    src_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime
    alerts: list[Alert] = Field(default_factory=list)
    sample_events: list[str] = Field(default_factory=list)
