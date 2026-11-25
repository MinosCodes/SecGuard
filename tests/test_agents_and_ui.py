"""Tests for Hermes stream-json parsing, multi-agent orchestration, and FastAPI UI."""

from pathlib import Path

from fastapi.testclient import TestClient

from secguard.agents import (
    HermesTurnResult,
    MultiAgentOrchestrator,
    parse_stream_json_line,
)
from secguard.config import AppConfig
from secguard.ui import create_app


def test_parse_stream_json_line() -> None:
    assert parse_stream_json_line("Warning: Unknown toolsets: none") is None
    assert parse_stream_json_line("") is None
    ev = parse_stream_json_line('{"type": "system", "session_id": "s-123", "model": "Gemma4:12b"}')
    assert ev is not None
    assert ev["session_id"] == "s-123"


class _FakeHermesRunner:
    def run_prompt(self, profile: str, prompt: str, model=None, on_event=None) -> HermesTurnResult:
        if on_event:
            on_event({"type": "system", "session_id": f"sess-{profile}", "model": model or "Gemma4:12b"})
        if profile == "secguard-hunter":
            text = (
                '{"verdict": "TRUE_POSITIVE", "severity": "CRITICAL", "confidence": 0.96, '
                '"attack_narrative": "SSH brute force succeeded, shadow read, curl|bash, useradd, and injection.", '
                '"mitre_techniques": ["T1110.001", "T1078", "T1562"], '
                '"iocs": ["IP: 185.220.101.42", "IP: 203.0.113.55"], '
                '"prompt_injection_detected": true}'
            )
        elif profile == "secguard-responder":
            text = (
                '{"containment_priority": "IMMEDIATE", '
                '"recommended_actions": ["Block 185.220.101.42", "Rotate devops credentials"], '
                '"verification_checks": ["Check /etc/passwd and authorized_keys"]}'
            )
        else:
            text = '{"executive_summary": "Confirmed CRITICAL SSH compromise and persistence; prompt injection neutralized."}'
        return HermesTurnResult(
            text=text,
            session_id=f"sess-{profile}",
            model=model or "Gemma4:12b",
            input_tokens=400,
            output_tokens=90,
            duration_ms=450,
            exit_code=0,
        )


def test_orchestrator_attack_and_benign(tmp_path: Path) -> None:
    cfg = AppConfig()
    cfg.rag.enabled = False
    cfg.hermes.runs_dir = str(tmp_path / "runs")

    updates: list[str] = []
    orch = MultiAgentOrchestrator(
        config=cfg,
        on_update=lambda st, ev: updates.append(f"{ev.agent}:{ev.kind}"),
        hermes_runner=_FakeHermesRunner(),  # type: ignore[arg-type]
    )

    attack_state = orch.run(
        Path("samples/linux_attack_scenario.log"),
        output_dir=tmp_path / "attack_out",
        backend="hermes",
    )
    assert attack_state.status == "completed"
    assert attack_state.overall_risk == "CRITICAL"
    assert attack_state.verdict == "TRUE_POSITIVE"
    assert attack_state.prompt_injection_detected is True
    assert all(t.status == "completed" for t in attack_state.tasks)
    assert Path(attack_state.report_files["md"]).exists()
    assert Path(attack_state.report_files["html"]).exists()
    assert Path(attack_state.report_files["json"]).exists()
    assert len(updates) >= 6

    benign_state = orch.run(
        Path("samples/linux_benign_baseline.log"),
        output_dir=tmp_path / "benign_out",
        backend="hermes",
    )
    assert benign_state.status == "completed"
    assert benign_state.overall_risk == "LOW"
    assert benign_state.verdict == "CLEAN"
    assert benign_state.tasks[2].status == "skipped"
    assert benign_state.tasks[3].status == "skipped"
    assert benign_state.tasks[4].status == "skipped"
    assert benign_state.tasks[5].status == "completed"


def test_fastapi_ui_endpoints(tmp_path: Path) -> None:
    cfg = AppConfig()
    cfg.rag.enabled = False
    cfg.hermes.runs_dir = str(tmp_path / "runs")

    orch = MultiAgentOrchestrator(
        config=cfg,
        hermes_runner=_FakeHermesRunner(),  # type: ignore[arg-type]
    )
    saved = orch.run(Path("samples/linux_attack_scenario.log"), output_dir=tmp_path / "rep")

    app = create_app(cfg)
    client = TestClient(app)

    r_home = client.get("/")
    assert r_home.status_code == 200
    assert "SecGuard" in r_home.text

    r_agents = client.get("/api/agents")
    assert r_agents.status_code == 200
    names = [a["name"] for a in r_agents.json()["agents"]]
    assert names == ["secguard-collector", "secguard-hunter", "secguard-responder", "secguard-reporter"]

    r_samples = client.get("/api/samples")
    assert r_samples.status_code == 200
    assert any("linux_attack_scenario.log" in s for s in r_samples.json()["samples"])

    r_runs = client.get("/api/runs")
    assert r_runs.status_code == 200
    assert any(r["run_id"] == saved.run_id for r in r_runs.json()["runs"])

    r_detail = client.get(f"/api/runs/{saved.run_id}")
    assert r_detail.status_code == 200
    assert r_detail.json()["overall_risk"] == "CRITICAL"

    r_rep = client.get(f"/api/runs/{saved.run_id}/report/html")
    assert r_rep.status_code == 200
    assert "CRITICAL" in r_rep.text
