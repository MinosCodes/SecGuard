"""Alert correlation into unified incident clusters."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from secguard.config import DetectionConfig
from secguard.detectors.models import Alert, IncidentCluster, Severity, severity_rank


def correlate_alerts(alerts: list[Alert], config: DetectionConfig) -> list[IncidentCluster]:
    """Group related alerts sharing IP, user, or close temporal proximity into IncidentClusters."""
    if not alerts:
        return []

    n = len(alerts)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    gap = timedelta(seconds=config.correlation_gap_seconds)

    for i in range(n):
        for j in range(i + 1, n):
            ai, aj = alerts[i], alerts[j]
            close_in_time = (
                ai.start_time - gap <= aj.end_time and aj.start_time - gap <= ai.end_time
            )
            if not close_in_time:
                continue

            same_ip = bool(ai.src_ip and aj.src_ip and ai.src_ip == aj.src_ip)
            same_user = bool(ai.user and aj.user and ai.user == aj.user)
            # Link post-compromise execution (no src_ip) to an active compromise incident within tight window
            tight_post_compromise = (
                (ai.rule_id == "SSH_BRUTE_FORCE_SUCCESS" or aj.rule_id == "SSH_BRUTE_FORCE_SUCCESS")
                and abs((ai.start_time - aj.start_time).total_seconds()) <= 600
            )
            if same_ip or same_user or tight_post_compromise:
                union(i, j)

    groups: dict[int, list[Alert]] = defaultdict(list)
    for idx, alert in enumerate(alerts):
        groups[find(idx)].append(alert)

    clusters: list[IncidentCluster] = []
    for group_alerts in groups.values():
        group_alerts.sort(key=lambda a: (a.start_time, -severity_rank(a.severity)))
        max_sev = max(group_alerts, key=lambda a: severity_rank(a.severity)).severity
        src_ips = sorted({a.src_ip for a in group_alerts if a.src_ip})
        users = sorted({a.user for a in group_alerts if a.user})
        techniques = sorted({t for a in group_alerts for t in a.mitre_techniques})

        seen_raw: set[str] = set()
        samples: list[str] = []
        for a in group_alerts:
            for ev in a.evidence:
                if ev not in seen_raw:
                    seen_raw.add(ev)
                    samples.append(ev)

        top_alert = max(group_alerts, key=lambda a: severity_rank(a.severity))
        title = top_alert.title
        if len(group_alerts) > 1:
            actor = ", ".join(src_ips) if src_ips else (", ".join(users) if users else "local host")
            title = f"Correlated {max_sev.value} incident ({actor}): {top_alert.title}"

        clusters.append(
            IncidentCluster(
                incident_id="",
                title=title,
                severity=max_sev,
                src_ips=src_ips,
                users=users,
                mitre_techniques=techniques,
                start_time=min(a.start_time for a in group_alerts),
                end_time=max(a.end_time for a in group_alerts),
                alerts=group_alerts,
                sample_events=samples,
            )
        )

    clusters.sort(key=lambda c: (-severity_rank(c.severity), c.start_time))
    for idx, cluster in enumerate(clusters, start=1):
        cluster.incident_id = f"INC-{idx:03d}"

    return clusters
