"""Lightweight ML (IsolationForest + MAD z-score) behavioral anomaly detection."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import IsolationForest

from secguard.config import DetectionConfig
from secguard.detectors.models import Alert, Severity
from secguard.parsers.models import LogEvent

_FEATURE_NAMES = [
    "event_count",
    "failed_count",
    "failure_ratio",
    "unique_users",
    "unique_commands",
    "priv_exec_count",
    "off_hours_ratio",
    "avg_cmd_len",
]


def _bucket_start(ts: datetime, bucket_minutes: int) -> datetime:
    ts_utc = ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    floored_min = (ts_utc.minute // bucket_minutes) * bucket_minutes
    return ts_utc.replace(minute=floored_min, second=0, microsecond=0)


def _robust_zscores(matrix: np.ndarray) -> np.ndarray:
    """Compute modified z-scores using median and MAD."""
    medians = np.median(matrix, axis=0)
    abs_dev = np.abs(matrix - medians)
    mad = np.median(abs_dev, axis=0)
    # Fallback to std if MAD is zero, else 1.0 to avoid div-by-zero
    stds = np.std(matrix, axis=0)
    scale = np.where(mad > 1e-6, 1.4826 * mad, np.where(stds > 1e-6, stds, 1.0))
    return (matrix - medians) / scale


def detect_anomalies(events: list[LogEvent], config: DetectionConfig) -> list[Alert]:
    """Detect behavioral anomalies over entity/time feature buckets."""
    if not events:
        return []

    buckets: dict[tuple[str, datetime], list[LogEvent]] = defaultdict(list)
    for ev in events:
        entity = ev.src_ip or (f"user:{ev.user}" if ev.user else f"host:{ev.host}")
        b_start = _bucket_start(ev.timestamp, config.anomaly_bucket_minutes)
        buckets[(entity, b_start)].append(ev)

    if len(buckets) < 2:
        return []

    keys = sorted(buckets.keys(), key=lambda k: (k[1], k[0]))
    rows: list[list[float]] = []

    for entity, b_start in keys:
        b_events = buckets[(entity, b_start)]
        ev_count = float(len(b_events))
        failed = float(sum(1 for e in b_events if e.outcome == "failure"))
        fail_ratio = failed / ev_count if ev_count else 0.0
        uniq_users = float(len({e.user for e in b_events if e.user}))
        cmds = [e.command for e in b_events if e.command]
        uniq_cmds = float(len(set(cmds)))
        priv_exec = float(
            sum(
                1
                for e in b_events
                if e.event_type in {"sudo_exec", "sudo_unauthorized", "auditd_execve", "account_change"}
            )
        )
        off_hours = float(
            sum(
                1
                for e in b_events
                if (e.timestamp.astimezone(timezone.utc).hour < 6 or e.timestamp.astimezone(timezone.utc).hour >= 22)
            )
        ) / ev_count
        avg_cmd_len = float(sum(len(c) for c in cmds) / len(cmds)) if cmds else 0.0

        rows.append([ev_count, failed, fail_ratio, uniq_users, uniq_cmds, priv_exec, off_hours, avg_cmd_len])

    X = np.array(rows, dtype=float)
    zscores = _robust_zscores(X)

    iso_preds: np.ndarray | None = None
    if len(keys) >= 8:
        iso = IsolationForest(
            contamination=min(max(config.anomaly_contamination, 0.01), 0.45),
            random_state=42,
            n_estimators=100,
        )
        iso_preds = iso.fit_predict(X)

    alerts: list[Alert] = []
    alert_idx = 0

    for idx, (entity, b_start) in enumerate(keys):
        feat_map = dict(zip(_FEATURE_NAMES, [round(float(v), 3) for v in rows[idx]]))
        row_z = zscores[idx]
        max_z = float(np.max(row_z))

        # Gate on security-relevant elevation so normal baseline variance never false-positives
        security_elevated = (
            feat_map["failed_count"] >= 3.0
            or (feat_map["failure_ratio"] >= 0.5 and feat_map["event_count"] >= 3.0)
            or feat_map["priv_exec_count"] >= 3.0
            or feat_map["event_count"] >= 12.0
            or feat_map["unique_users"] >= 4.0
        )
        if not security_elevated:
            continue

        is_iso_outlier = bool(iso_preds is not None and iso_preds[idx] == -1)
        is_stat_outlier = max_z >= 3.0

        if not (is_iso_outlier or is_stat_outlier):
            continue

        alert_idx += 1
        b_events = sorted(buckets[(entity, b_start)], key=lambda e: e.timestamp)
        top_drivers = sorted(
            [(name, float(row_z[i]), feat_map[name]) for i, name in enumerate(_FEATURE_NAMES) if row_z[i] > 1.5],
            key=lambda item: item[1],
            reverse=True,
        )[:3]
        driver_desc = ", ".join(f"{n}={val} (z={z:.1f})" for n, z, val in top_drivers) or f"event_count={feat_map['event_count']}"

        src_ip = None if entity.startswith(("user:", "host:")) else entity
        user = entity.removeprefix("user:") if entity.startswith("user:") else None
        if not user:
            users_in_bucket = {e.user for e in b_events if e.user}
            if len(users_in_bucket) == 1:
                user = next(iter(users_in_bucket))

        severity = Severity.HIGH if (feat_map["failed_count"] >= 6 or feat_map["priv_exec_count"] >= 4) else Severity.MEDIUM
        confidence = min(0.95, 0.65 + 0.05 * min(max_z, 6.0))

        alerts.append(
            Alert(
                id=f"ANOM-{alert_idx:04d}",
                detector="isolation_forest" if is_iso_outlier else "mad_zscore",
                rule_id="ANOMALY_BEHAVIORAL",
                title=f"Behavioral anomaly detected for {entity}",
                severity=severity,
                confidence=round(confidence, 2),
                mitre_techniques=["T1110"] if feat_map["failed_count"] >= 3 else ["T1078"],
                start_time=b_events[0].timestamp,
                end_time=b_events[-1].timestamp,
                src_ip=src_ip,
                user=user,
                event_count=len(b_events),
                summary=f"Outlier activity window for {entity} ({len(b_events)} events): {driver_desc}.",
                evidence=[e.raw for e in b_events[:6]],
                features=feat_map,
            )
        )

    return alerts
