"""Tests for deterministic rules, IsolationForest anomaly detection, and alert correlation."""

from pathlib import Path

from secguard.config import DetectionConfig
from secguard.detectors import (
    Severity,
    correlate_alerts,
    detect_anomalies,
    detect_rule_alerts,
)
from secguard.parsers import parse_log_file, parse_log_lines


def test_benign_baseline_produces_zero_alerts() -> None:
    cfg = DetectionConfig()
    events = parse_log_file(Path("samples/linux_benign_baseline.log"))
    rule_alerts = detect_rule_alerts(events, cfg)
    anom_alerts = detect_anomalies(events, cfg)
    assert rule_alerts == []
    assert anom_alerts == []


def test_attack_rules_and_correlation() -> None:
    cfg = DetectionConfig()
    events = parse_log_file(Path("samples/linux_attack_scenario.log"))
    rule_alerts = detect_rule_alerts(events, cfg)
    anom_alerts = detect_anomalies(events, cfg)
    all_alerts = rule_alerts + anom_alerts

    rule_ids = {a.rule_id for a in rule_alerts}
    assert "SSH_BRUTE_FORCE" in rule_ids
    assert "SSH_PASSWORD_SPRAY" in rule_ids
    assert "SSH_BRUTE_FORCE_SUCCESS" in rule_ids
    assert "SUSPICIOUS_PRIV_EXEC" in rule_ids
    assert "ACCOUNT_PERSISTENCE" in rule_ids
    assert "LOG_PROMPT_INJECTION" in rule_ids

    assert any(a.rule_id == "ANOMALY_BEHAVIORAL" for a in anom_alerts)

    clusters = correlate_alerts(all_alerts, cfg)
    assert len(clusters) >= 1
    assert clusters[0].severity == Severity.CRITICAL
    assert "185.220.101.42" in clusters[0].src_ips


def test_unauthorized_sudo_rule() -> None:
    cfg = DetectionConfig()
    events = parse_log_lines(
        [
            "2026-11-25T10:00:01+00:00 web01 sudo: guest : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
        ]
    )
    alerts = detect_rule_alerts(events, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SUDO_UNAUTHORIZED"
    assert "T1548.003" in alerts[0].mitre_techniques
