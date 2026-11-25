"""Configuration models and loader for SecGuard LLM."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class OllamaConfig(BaseModel):
    base_url: str = "http://127.0.0.1:11434"
    model: str = "phi4:latest"
    embed_model: str = "nomic-embed-text:latest"
    timeout_seconds: float = 300.0
    num_ctx: int = 4096
    num_predict: int = 900
    temperature: float = 0.1
    disable_thinking: bool = True
    keep_alive: str = "5m"
    benchmark_models: list[str] = Field(
        default_factory=lambda: [
            "phi4:latest",
            "Gemma4:12b",
            "qwen-abliterated:latest",
        ]
    )


class DetectionConfig(BaseModel):
    ssh_brute_force_threshold: int = 5
    ssh_spray_user_threshold: int = 4
    window_seconds: int = 300
    correlation_gap_seconds: int = 1800
    anomaly_bucket_minutes: int = 5
    anomaly_contamination: float = 0.15


class SanitizerConfig(BaseModel):
    max_line_chars: int = 240
    max_evidence_lines: int = 25


class RagConfig(BaseModel):
    enabled: bool = True
    top_k: int = 4
    cache_path: str = ".cache/mitre_kb_embeddings.json"


class HermesConfig(BaseModel):
    enabled: bool = True
    executable: str = "hermes"
    provider: str = "ollama-launch"
    model: str = "Gemma4:12b"
    reasoning: str = "none"
    timeout_seconds: float = 180.0
    runs_dir: str = "reports/agent_runs"


class AppConfig(BaseModel):
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    sanitizer: SanitizerConfig = Field(default_factory=SanitizerConfig)
    rag: RagConfig = Field(default_factory=RagConfig)
    hermes: HermesConfig = Field(default_factory=HermesConfig)


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load configuration from YAML and apply SECGUARD_* environment overrides."""
    data: dict[str, Any] = {}
    candidate = config_path or Path("config.yaml")
    if candidate.exists():
        raw = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            data = raw

    cfg = AppConfig.model_validate(data)

    if env_url := os.getenv("SECGUARD_OLLAMA_URL"):
        cfg.ollama.base_url = env_url
    if env_model := os.getenv("SECGUARD_MODEL"):
        cfg.ollama.model = env_model
    if env_embed := os.getenv("SECGUARD_EMBED_MODEL"):
        cfg.ollama.embed_model = env_embed

    return cfg
