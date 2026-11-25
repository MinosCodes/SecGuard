"""Hermes Agent profile management and subprocess runner wrapping local Ollama."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import BaseModel

from secguard.agents.models import AgentBlueprint
from secguard.config import AppConfig

_DEFAULT_BLUEPRINTS_PATH = Path(__file__).resolve().parents[3] / "agents" / "profiles.yaml"


class HermesTurnResult(BaseModel):
    text: str
    session_id: str | None = None
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
    exit_code: int = 0
    error: str | None = None


def hermes_home_dir() -> Path:
    """Locate the local Hermes state/profiles directory on Windows or Linux."""
    if env_home := os.getenv("HERMES_HOME"):
        return Path(env_home)
    if os.name == "nt":
        local_app = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "hermes"
        if local_app.exists():
            return local_app
    return Path.home() / ".hermes"


def load_blueprints(path: Path | None = None) -> list[AgentBlueprint]:
    """Load SecGuard Hermes agent blueprints from YAML."""
    target = path or (Path("agents/profiles.yaml") if Path("agents/profiles.yaml").exists() else _DEFAULT_BLUEPRINTS_PATH)
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    items = raw.get("agents", [])
    return [AgentBlueprint.model_validate(item) for item in items]


def list_installed_hermes_profiles(hermes_exe: str = "hermes") -> set[str]:
    """Return the set of locally installed Hermes profile names."""
    profiles: set[str] = set()
    profiles_dir = hermes_home_dir() / "profiles"
    if profiles_dir.exists():
        for child in profiles_dir.iterdir():
            if child.is_dir():
                profiles.add(child.name)

    try:
        proc = subprocess.run(
            [hermes_exe, "profile", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if proc.returncode == 0:
            for raw_line in proc.stdout.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("Profile", "─", "—", "Usage")):
                    continue
                token = line.lstrip("◆•* ").split()[0]
                if token:
                    profiles.add(token)
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    return profiles


def bootstrap_hermes_profiles(
    config: AppConfig,
    model_override: str | None = None,
    blueprints_path: Path | None = None,
) -> list[dict[str, str]]:
    """Idempotently create and configure the SecGuard Hermes agent profiles with SOUL.md + Ollama."""
    blueprints = load_blueprints(blueprints_path)
    installed = list_installed_hermes_profiles(config.hermes.executable)
    chosen_model = model_override or config.hermes.model
    results: list[dict[str, str]] = []

    for bp in blueprints:
        action = "updated"
        if bp.name not in installed:
            proc = subprocess.run(
                [
                    config.hermes.executable,
                    "profile",
                    "create",
                    bp.name,
                    "--clone",
                    "--no-alias",
                    "--description",
                    bp.description,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"Failed to create Hermes profile '{bp.name}': {proc.stderr or proc.stdout}"
                )
            action = "created"

        profile_dir = hermes_home_dir() / "profiles" / bp.name
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "SOUL.md").write_text(bp.soul.strip() + "\n", encoding="utf-8")

        cfg_file = profile_dir / "config.yaml"
        profile_cfg: dict[str, Any] = {}
        if cfg_file.exists():
            loaded = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                profile_cfg = loaded
        model_section = profile_cfg.setdefault("model", {})
        if isinstance(model_section, dict):
            model_section["default"] = chosen_model
            model_section["provider"] = config.hermes.provider
            model_section["base_url"] = f"{config.ollama.base_url.rstrip('/')}/v1"
            model_section["api_key"] = "ollama"
        cfg_file.write_text(yaml.safe_dump(profile_cfg, sort_keys=False), encoding="utf-8")

        results.append(
            {
                "name": bp.name,
                "role": bp.role,
                "status": action,
                "model": chosen_model,
                "path": str(profile_dir),
            }
        )

    return results


def parse_stream_json_line(line: str) -> dict[str, Any] | None:
    """Parse a single JSONL line emitted by `hermes chat --format stream-json`."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


class HermesOllamaRunner:
    """Executes single-turn Hermes Agent prompts backed by local Ollama via stream-json."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run_prompt(
        self,
        profile: str,
        prompt: str,
        model: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> HermesTurnResult:
        """Invoke a Hermes profile in oneshot stream-json mode and stream events."""
        chosen_model = model or self.config.hermes.model
        installed = list_installed_hermes_profiles(self.config.hermes.executable)
        use_profile = profile if profile in installed else None

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".txt",
            delete=False,
        ) as tmp:
            tmp.write(prompt)
            query_file = Path(tmp.name)

        cmd: list[str] = [self.config.hermes.executable]
        if use_profile:
            cmd.extend(["-p", use_profile])
        cmd.extend(
            [
                "chat",
                "--query-file",
                str(query_file),
                "--oneshot",
                "--format",
                "stream-json",
                "--provider",
                self.config.hermes.provider,
                "-m",
                chosen_model,
                "--reasoning",
                self.config.hermes.reasoning,
                "-t",
                "none",
                "--max-turns",
                "1",
                "--ignore-rules",
                "--source",
                "tool",
            ]
        )

        text_chunks: list[str] = []
        session_id: str | None = None
        actual_model: str | None = chosen_model
        input_tokens = 0
        output_tokens = 0
        duration_ms = 0
        exit_code = 0
        error_msg: str | None = None
        non_json_lines: list[str] = []

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                ev = parse_stream_json_line(raw_line)
                if ev is None:
                    cleaned = raw_line.strip()
                    if cleaned:
                        non_json_lines.append(cleaned)
                    continue

                if on_event is not None:
                    on_event(ev)

                etype = ev.get("type")
                if etype == "system":
                    session_id = ev.get("session_id") or session_id
                    actual_model = ev.get("model") or actual_model
                elif etype == "text":
                    chunk = str(ev.get("text", ""))
                    if chunk:
                        text_chunks.append(chunk)
                elif etype == "result":
                    session_id = ev.get("session_id") or session_id
                    exit_code = int(ev.get("exit_code") or 0)
                    duration_ms = int(ev.get("duration_ms") or 0)
                    tokens = ev.get("tokens") or {}
                    if isinstance(tokens, dict):
                        input_tokens = int(tokens.get("input") or 0)
                        output_tokens = int(tokens.get("output") or 0)
                    if ev.get("text") and not text_chunks:
                        text_chunks.append(str(ev["text"]))
                    if ev.get("error"):
                        error_msg = str(ev["error"])

            proc.wait(timeout=self.config.hermes.timeout_seconds)
            stderr_text = proc.stderr.read().strip() if proc.stderr else ""
            if proc.returncode != 0 and exit_code == 0:
                exit_code = proc.returncode
            if exit_code != 0 and not error_msg:
                error_msg = stderr_text or " | ".join(non_json_lines[-3:]) or f"Hermes exited with {exit_code}"
        finally:
            query_file.unlink(missing_ok=True)

        full_text = "".join(text_chunks).strip()
        if exit_code != 0 and not full_text:
            raise RuntimeError(f"Hermes runner error ({profile}): {error_msg}")

        return HermesTurnResult(
            text=full_text,
            session_id=session_id,
            model=actual_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_ms=duration_ms,
            exit_code=exit_code,
            error=error_msg,
        )
