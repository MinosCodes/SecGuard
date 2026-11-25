"""Regression tests for detection accuracy, LLM guardrails, and API/daemon hardening fixes."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from secguard.config import AppConfig, DetectionConfig
from secguard.detectors import Severity, correlate_alerts, detect_rule_alerts
from secguard.detectors.models import Alert, IncidentCluster
from secguard.llm.triage import analyze_events, apply_guardrails
from secguard.parsers import parse_log_lines
from secguard.ui import create_app


def _cluster(*alerts: Alert) -> IncidentCluster:
    return IncidentCluster(
        incident_id="INC-001",
        title="test",
        severity=max(alerts, key=lambda a: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(a.severity.value)).severity,
        start_time=alerts[0].start_time,
        end_time=alerts[-1].end_time,
        alerts=list(alerts),
    )


def _alert(rule_id: str, severity: Severity, detector: str = "rule") -> Alert:
    now = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)
    return Alert(
        id="X",
        detector=detector,
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=0.9,
        start_time=now,
        end_time=now,
        summary=rule_id,
    )


def _ssh_fail(ts: datetime, user: str, ip: str = "198.51.100.7") -> str:
    return f"{ts.isoformat()} web01 sshd[1]: Failed password for {user} from {ip} port 4242 ssh2"


# --- LLM guardrails -------------------------------------------------------------------------


def test_guardrail_blocks_downgrade_of_any_high_rule_alert() -> None:
    # Previously only 3 specific rules were protected; a plain brute force could be talked down.
    cluster = _cluster(_alert("SSH_BRUTE_FORCE", Severity.HIGH))
    sev, verdict = apply_guardrails(cluster, Severity.LOW, "FALSE_POSITIVE")
    assert sev == Severity.HIGH
    assert verdict == "TRUE_POSITIVE"


def test_guardrail_leaves_anomaly_only_clusters_to_the_model() -> None:
    cluster = _cluster(_alert("ANOMALY_BEHAVIORAL", Severity.MEDIUM, detector="isolation_forest"))
    sev, verdict = apply_guardrails(cluster, Severity.LOW, "FALSE_POSITIVE")
    assert sev == Severity.LOW
    assert verdict == "FALSE_POSITIVE"


def test_llm_failure_falls_back_to_deterministic_triage() -> None:
    class _DeadClient:
        def chat_structured(self, *args, **kwargs):
            raise ConnectionError("Ollama is not running")

    cfg = AppConfig()
    cfg.rag.enabled = False
    base = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)
    events = parse_log_lines([_ssh_fail(base + timedelta(seconds=i), "root") for i in range(6)])

    report = analyze_events(events, cfg, log_source="test", use_llm=True, client=_DeadClient())

    assert report.incidents, "report should still contain the incident"
    assert report.overall_risk == Severity.HIGH
    assert "deterministic triage was used" in report.executive_summary


# --- Detection accuracy ---------------------------------------------------------------------


def test_brute_force_bursts_days_apart_are_separate_alerts() -> None:
    day1 = datetime(2026, 11, 24, 10, 0, tzinfo=timezone.utc)
    day2 = day1 + timedelta(days=1)
    lines = [_ssh_fail(day1 + timedelta(seconds=i), "root") for i in range(5)]
    lines += [_ssh_fail(day2 + timedelta(seconds=i), "root") for i in range(5)]

    alerts = [a for a in detect_rule_alerts(parse_log_lines(lines), DetectionConfig()) if a.rule_id == "SSH_BRUTE_FORCE"]

    assert len(alerts) == 2
    assert all(a.event_count == 5 for a in alerts)
    assert alerts[0].end_time < alerts[1].start_time


def test_password_spray_detected_below_brute_force_threshold() -> None:
    base = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)
    # 4 attempts (< brute-force threshold of 5) against 4 different accounts
    lines = [_ssh_fail(base + timedelta(seconds=i), u) for i, u in enumerate(["alice", "bob", "carol", "dave"])]

    rule_ids = {a.rule_id for a in detect_rule_alerts(parse_log_lines(lines), DetectionConfig())}

    assert "SSH_PASSWORD_SPRAY" in rule_ids
    assert "SSH_BRUTE_FORCE" not in rule_ids


def test_ipv6_ssh_sources_are_parsed() -> None:
    events = parse_log_lines(
        ["2026-11-25T10:00:00+00:00 web01 sshd[1]: Failed password for root from 2001:db8::42 port 2222 ssh2"]
    )
    assert events[0].event_type == "ssh_failed_auth"
    assert events[0].src_ip == "2001:db8::42"
    assert events[0].src_port == 2222


def test_reading_etc_passwd_is_not_account_persistence() -> None:
    base = "2026-11-25T10:00:00+00:00 web01 sudo: ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND="
    benign = detect_rule_alerts(parse_log_lines([base + "/usr/bin/cat /etc/passwd"]), DetectionConfig())
    assert not any(a.rule_id == "ACCOUNT_PERSISTENCE" for a in benign)

    real = detect_rule_alerts(parse_log_lines([base + "/usr/bin/passwd bob"]), DetectionConfig())
    assert any(a.rule_id == "ACCOUNT_PERSISTENCE" for a in real)


def test_rfc3164_year_rolls_back_instead_of_landing_in_future() -> None:
    future = datetime.now(timezone.utc) + timedelta(days=3)
    line = f"{future.strftime('%b')} {future.day:2d} 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ts = parse_log_lines([line])[0].timestamp
    assert ts < datetime.now(timezone.utc)
    assert ts.year == future.year - 1


def test_attack_scenario_still_correlates_to_one_critical_incident() -> None:
    cfg = DetectionConfig()
    events = parse_log_lines(Path("samples/linux_attack_scenario.log").read_text(encoding="utf-8").splitlines())
    clusters = correlate_alerts(detect_rule_alerts(events, cfg), cfg)
    assert clusters[0].severity == Severity.CRITICAL


# --- Web API hardening ----------------------------------------------------------------------


def test_ui_rejects_log_paths_outside_allowed_dirs() -> None:
    client = TestClient(create_app(AppConfig()))

    for path in ["pyproject.toml", "../../../etc/shadow", "samples/../pyproject.toml"]:
        resp = client.post("/api/runs", json={"log_path": path, "backend": "ollama"})
        assert resp.status_code == 403, path

    assert client.post("/api/runs", json={"log_path": "samples/missing.log"}).status_code == 400


def test_ui_serves_agent_office_script() -> None:
    client = TestClient(create_app(AppConfig()))
    page = client.get("/")
    script = client.get("/static/office.js")
    assert 'id="officeCanvas"' in page.text
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert "SecGuardOffice" in script.text


def test_ui_rejects_malformed_run_ids() -> None:
    client = TestClient(create_app(AppConfig()))
    assert client.get("/api/runs/..%5C..%5Cconfig").status_code == 404
