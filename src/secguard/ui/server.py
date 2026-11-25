"""FastAPI server providing live SSE streaming and history for SecGuard Hermes agents."""

from __future__ import annotations

import asyncio
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from secguard.agents.hermes_runner import list_installed_hermes_profiles, load_blueprints
from secguard.agents.models import AgentEvent, AgentRunState
from secguard.agents.orchestrator import MultiAgentOrchestrator
from secguard.config import AppConfig, load_config

_STATIC_INDEX = Path(__file__).with_name("static") / "index.html"
_RUN_ID_RE = re.compile(r"RUN-[0-9A-Za-z-]{1,64}")


class StartRunRequest(BaseModel):
    log_path: str = "samples/linux_attack_scenario.log"
    model: str | None = None
    backend: Literal["hermes", "ollama"] = "hermes"


def create_app(config: AppConfig | None = None) -> FastAPI:
    """Create and configure the SecGuard Agent Visualizer FastAPI app."""
    cfg = config or load_config()
    app = FastAPI(title="SecGuard Hermes Agent Visualizer", version="0.1.0")

    active_runs: dict[str, AgentRunState] = {}
    subscribers: dict[str, list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[str | None]]]] = {}
    lock = threading.Lock()

    def _broadcast(run_id: str, state: AgentRunState) -> None:
        payload = state.model_dump_json()
        with lock:
            active_runs[run_id] = state
            subs = list(subscribers.get(run_id, []))
        for loop, queue in subs:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, payload)
                if state.status in {"completed", "failed"}:
                    loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:
                # Subscriber's event loop already closed (client gone); this must not
                # propagate into the orchestrator and fail the run.
                continue

    def _load_disk_runs() -> list[AgentRunState]:
        runs_dir = Path(cfg.hermes.runs_dir)
        if not runs_dir.exists():
            return []
        loaded: list[AgentRunState] = []
        for path in runs_dir.glob("RUN-*.json"):
            try:
                loaded.append(AgentRunState.model_validate_json(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return loaded

    def _get_run(run_id: str) -> AgentRunState | None:
        if not _RUN_ID_RE.fullmatch(run_id):  # run_id becomes part of a file path below
            return None
        with lock:
            if run_id in active_runs:
                return active_runs[run_id]
        disk_path = Path(cfg.hermes.runs_dir) / f"{run_id}.json"
        if disk_path.exists():
            return AgentRunState.model_validate_json(disk_path.read_text(encoding="utf-8"))
        return None

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        if not _STATIC_INDEX.exists():
            raise HTTPException(status_code=404, detail="UI index.html missing")
        return HTMLResponse(_STATIC_INDEX.read_text(encoding="utf-8"))

    @app.get("/api/agents")
    def get_agents() -> dict[str, Any]:
        blueprints = load_blueprints()
        installed = list_installed_hermes_profiles(cfg.hermes.executable)
        return {
            "hermes_model": cfg.hermes.model,
            "ollama_model": cfg.ollama.model,
            "provider": cfg.hermes.provider,
            "agents": [
                {
                    **bp.model_dump(),
                    "installed": bp.name in installed,
                }
                for bp in blueprints
            ],
        }

    @app.get("/api/samples")
    def get_samples() -> dict[str, list[str]]:
        samples_dir = Path("samples")
        files = sorted(str(p).replace("\\", "/") for p in samples_dir.glob("*.log")) if samples_dir.exists() else []
        return {"samples": files}

    @app.get("/api/runs")
    def list_runs() -> dict[str, list[dict[str, Any]]]:
        merged: dict[str, AgentRunState] = {}
        for r in _load_disk_runs():
            merged[r.run_id] = r
        with lock:
            for r_id, r in active_runs.items():
                merged[r_id] = r
        ordered = sorted(merged.values(), key=lambda r: r.started_at, reverse=True)
        return {
            "runs": [
                {
                    "run_id": r.run_id,
                    "log_source": r.log_source,
                    "backend": r.backend,
                    "model": r.model,
                    "status": r.status,
                    "overall_risk": r.overall_risk,
                    "verdict": r.verdict,
                    "started_at": r.started_at.isoformat(),
                    "total_alerts": r.total_alerts,
                    "prompt_injection_detected": r.prompt_injection_detected,
                }
                for r in ordered
            ]
        }

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        run_state = _get_run(run_id)
        if run_state is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return json.loads(run_state.model_dump_json())

    allowed_roots = [Path(d).resolve() for d in cfg.ui.allowed_log_dirs]

    def _resolve_allowed_log(raw_path: str) -> Path:
        candidate = Path(raw_path).resolve()
        if not any(candidate.is_relative_to(root) for root in allowed_roots):
            raise HTTPException(
                status_code=403,
                detail="Log path is outside the allowed log directories (see ui.allowed_log_dirs in config.yaml).",
            )
        if not candidate.is_file():
            raise HTTPException(status_code=400, detail=f"Log file not found: {raw_path}")
        return candidate

    @app.post("/api/runs", status_code=202)
    def start_run(req: StartRunRequest) -> dict[str, str]:
        log_path = _resolve_allowed_log(req.log_path)

        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        chosen_model = req.model or (cfg.hermes.model if req.backend == "hermes" else cfg.ollama.model)
        orch = MultiAgentOrchestrator(
            config=cfg,
            on_update=lambda st, _ev: _broadcast(run_id, st),
        )
        initial = orch._build_initial_state(run_id, log_path, backend=req.backend, model=chosen_model)
        with lock:
            active_runs[run_id] = initial

        def _worker() -> None:
            try:
                final_state = orch.run(
                    log_path=log_path,
                    model_override=chosen_model,
                    backend=req.backend,
                    run_id=run_id,
                )
                _broadcast(run_id, final_state)
            except Exception:
                # Orchestrator already emitted run_error and persisted state
                pass

        thread = threading.Thread(target=_worker, daemon=True, name=f"secguard-{run_id}")
        thread.start()
        return {"run_id": run_id}

    @app.get("/api/runs/{run_id}/stream")
    async def stream_run(run_id: str) -> StreamingResponse:
        run_state = _get_run(run_id)
        if run_state is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        with lock:
            subscribers.setdefault(run_id, []).append((loop, queue))

        async def _event_gen():
            try:
                yield f"event: update\ndata: {run_state.model_dump_json()}\n\n"
                if run_state.status in {"completed", "failed"}:
                    return
                while True:
                    item = await queue.get()
                    if item is None:
                        break
                    yield f"event: update\ndata: {item}\n\n"
            finally:
                with lock:
                    subs = subscribers.get(run_id, [])
                    subscribers[run_id] = [(lp, q) for lp, q in subs if q is not queue]

        return StreamingResponse(_event_gen(), media_type="text/event-stream")

    @app.get("/api/runs/{run_id}/report/{fmt}")
    def get_run_report(run_id: str, fmt: Literal["html", "md", "json"]) -> Any:
        run_state = _get_run(run_id)
        if run_state is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        target = run_state.report_files.get(fmt)
        if not target or not Path(target).exists():
            raise HTTPException(status_code=404, detail=f"Report format '{fmt}' not available for {run_id}")
        path = Path(target)
        if fmt == "html":
            return FileResponse(path, media_type="text/html; charset=utf-8")
        if fmt == "json":
            return FileResponse(path, media_type="application/json; charset=utf-8")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")

    return app
