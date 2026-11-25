"""Models for Hermes-wrapped multi-agent execution and live visualization."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

AgentStatus = Literal["idle", "running", "completed", "error"]
TaskStatus = Literal["queued", "in_progress", "completed", "skipped", "failed"]


class AgentBlueprint(BaseModel):
    name: str
    role: str
    uses_llm: bool = True
    description: str
    soul: str


class AgentRuntimeState(BaseModel):
    name: str
    role: str
    uses_llm: bool = True
    status: AgentStatus = "idle"
    current_task_id: str | None = None
    session_id: str | None = None
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
    last_message: str = ""


class AgentTask(BaseModel):
    id: str
    title: str
    agent: str
    description: str
    status: TaskStatus = "queued"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    summary: str = ""
    artifacts: dict[str, Any] = Field(default_factory=dict)


class AgentEvent(BaseModel):
    seq: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent: str
    task_id: str | None = None
    kind: str = "info"
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class AgentRunState(BaseModel):
    run_id: str
    log_source: str
    backend: Literal["hermes", "ollama"] = "hermes"
    model: str
    status: Literal["running", "completed", "failed"] = "running"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    overall_risk: str = "LOW"
    verdict: str = "PENDING"
    total_events: int = 0
    total_alerts: int = 0
    total_incidents: int = 0
    prompt_injection_detected: bool = False
    executive_summary: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    report_files: dict[str, str] = Field(default_factory=dict)
    agents: dict[str, AgentRuntimeState] = Field(default_factory=dict)
    tasks: list[AgentTask] = Field(default_factory=list)
    events: list[AgentEvent] = Field(default_factory=list)
    error: str | None = None
