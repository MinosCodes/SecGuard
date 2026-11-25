"""Deterministic signature and behavioral rules for Linux security logs."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from secguard.config import DetectionConfig
from secguard.detectors.models import Alert, Severity
from secguard.parsers.models import LogEvent

_SSH_FAILURE_TYPES = {"ssh_failed_auth", "ssh_invalid_user", "ssh_pam_failure"}

_HIGH_RISK_CMD_PATTERNS: list[tuple[re.Pattern[str], str, list[str], Severity]] = [
    (
        re.compile(r"/etc/shadow|/etc/gshadow", re.IGNORECASE),
        "Sensitive credential file access (/etc/shadow)",
        ["T1003.008"],
        Severity.HIGH,
    ),
    (
        re.compile(r"(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        "Remote payload download piped directly to shell",
        ["T1059.004", "T1105"],
        Severity.CRITICAL,
    ),
    (
        re.compile(r"/dev/tcp/|\bnc\s+.*-e\b|\bncat\s+.*-e\b|\bmkfifo\b", re.IGNORECASE),
        "Potential reverse shell execution",
        ["T1059.004"],
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.IGNORECASE),
        "Base64-decoded payload execution",
        ["T1059.004"],
        Severity.HIGH,
    ),
    (
        re.compile(r"\bchmod\s+(?:[u+]*s|4[0-7]{3})\b", re.IGNORECASE),
        "SUID permission modification (privilege escalation risk)",
        ["T1548.001"],
        Severity.HIGH,
    ),
    (
        re.compile(r"authorized_keys", re.IGNORECASE),
        "SSH authorized_keys modification",
        ["T1098.004"],
        Severity.HIGH,
    ),
    (
        re.compile(r"\bcrontab\b|/etc/cron\.|/var/spool/cron", re.IGNORECASE),
        "Scheduled cron job tampering",
        ["T1053.003"],
        Severity.HIGH,
    ),
]

_ACCOUNT_PERSISTENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\buseradd\b", re.IGNORECASE),
    re.compile(r"\busermod\b.*\b(?:sudo|wheel|adm|root)\b", re.IGNORECASE),
    # Match the passwd *command* (incl. /usr/bin/passwd), not the /etc/passwd file -- reading it is routine.
    re.compile(r"(?<!/etc/)(?<![\w.-])passwd\b", re.IGNORECASE),
]

_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"mark\s+(?:all|this|everything|alerts?)\s+(?:as\s+)?benign", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
]


def _normalize_for_injection(text: str) -> str:
    return re.sub(r"[_\-\.\s]+", " ", text).strip()


def _split_bursts(events: list[LogEvent], gap: timedelta) -> list[list[LogEvent]]:
    """Split time-sorted events into bursts wherever consecutive events are more than `gap` apart."""
    bursts: list[list[LogEvent]] = []
    current: list[LogEvent] = []
    for ev in events:
        if current and ev.timestamp - current[-1].timestamp > gap:
            bursts.append(current)
            current = []
        current.append(ev)
    if current:
        bursts.append(current)
    return bursts


def _max_events_in_window(events: list[LogEvent], window: timedelta) -> int:
    """Largest number of time-sorted events that fall inside any sliding window of length `window`."""
    best = 0
    start = 0
    for end, ev in enumerate(events):
        while ev.timestamp - events[start].timestamp > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _next_id(counter: list[int]) -> str:
    counter[0] += 1
    return f"RULE-{counter[0]:04d}"


def detect_rule_alerts(events: list[LogEvent], config: DetectionConfig) -> list[Alert]:
    """Run deterministic cybersecurity detection rules over normalized LogEvents."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    counter = [0]
    window = timedelta(seconds=config.window_seconds)

    # 1. Group SSH events by source IP for brute force, spray, and post-brute-force success
    ssh_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for ev in sorted_events:
        if ev.src_ip and (ev.event_type in _SSH_FAILURE_TYPES or ev.event_type == "ssh_accepted"):
            ssh_by_ip[ev.src_ip].append(ev)

    for ip, ip_events in ssh_by_ip.items():
        failures = [e for e in ip_events if e.event_type in _SSH_FAILURE_TYPES]
        successes = [e for e in ip_events if e.event_type == "ssh_accepted"]

        # Split this IP's failures into separate bursts (activity separated by more than the
        # detection window), so attacks days apart become separate alerts with accurate timeframes.
        for burst in _split_bursts(failures, window):
            users = sorted({e.user for e in burst if e.user})
            if _max_events_in_window(burst, window) >= config.ssh_brute_force_threshold:
                alerts.append(
                    Alert(
                        id=_next_id(counter),
                        detector="rule",
                        rule_id="SSH_BRUTE_FORCE",
                        title=f"SSH brute-force attempt from {ip}",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        mitre_techniques=["T1110.001"],
                        start_time=burst[0].timestamp,
                        end_time=burst[-1].timestamp,
                        src_ip=ip,
                        user=users[0] if len(users) == 1 else None,
                        event_count=len(burst),
                        summary=f"Detected {len(burst)} failed SSH authentication events from {ip} targeting {len(users)} account(s).",
                        evidence=[e.raw for e in burst[:8]],
                    )
                )

            # Spraying is checked on its own: a few attempts against many accounts is exactly
            # the low-and-slow pattern that stays under the brute-force threshold.
            if len(users) >= config.ssh_spray_user_threshold:
                alerts.append(
                    Alert(
                        id=_next_id(counter),
                        detector="rule",
                        rule_id="SSH_PASSWORD_SPRAY",
                        title=f"SSH password spraying / user enumeration from {ip}",
                        severity=Severity.HIGH,
                        confidence=0.90,
                        mitre_techniques=["T1110.003"],
                        start_time=burst[0].timestamp,
                        end_time=burst[-1].timestamp,
                        src_ip=ip,
                        event_count=len(burst),
                        summary=f"Source IP {ip} targeted {len(users)} distinct usernames ({', '.join(users[:6])}).",
                        evidence=[e.raw for e in burst[:6]],
                    )
                )

        # Brute-force followed by successful login
        if failures and successes:
            for succ in successes:
                prior_fails = [
                    f
                    for f in failures
                    if timedelta(0) <= (succ.timestamp - f.timestamp) <= timedelta(seconds=config.correlation_gap_seconds)
                ]
                if len(prior_fails) >= 3:
                    combined = prior_fails[-5:] + [succ]
                    alerts.append(
                        Alert(
                            id=_next_id(counter),
                            detector="rule",
                            rule_id="SSH_BRUTE_FORCE_SUCCESS",
                            title=f"Successful SSH login after brute-force from {ip} as '{succ.user}'",
                            severity=Severity.CRITICAL,
                            confidence=0.97,
                            mitre_techniques=["T1110.001", "T1078"],
                            start_time=prior_fails[0].timestamp,
                            end_time=succ.timestamp,
                            src_ip=ip,
                            user=succ.user,
                            event_count=len(prior_fails) + 1,
                            summary=(
                                f"IP {ip} recorded {len(prior_fails)} failed SSH attempts followed by an "
                                f"accepted {succ.metadata.get('auth_method', 'ssh')} login for '{succ.user}'."
                            ),
                            evidence=[e.raw for e in combined],
                        )
                    )
                    break

    # 2. Unauthorized sudo or repeated sudo auth failures
    sudo_unauth = [e for e in sorted_events if e.event_type in {"sudo_unauthorized", "sudo_auth_failure"}]
    if sudo_unauth:
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in sudo_unauth:
            by_user[ev.user or "unknown"].append(ev)
        for user, u_events in by_user.items():
            alerts.append(
                Alert(
                    id=_next_id(counter),
                    detector="rule",
                    rule_id="SUDO_UNAUTHORIZED",
                    title=f"Unauthorized sudo attempt by '{user}'",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    mitre_techniques=["T1548.003"],
                    start_time=u_events[0].timestamp,
                    end_time=u_events[-1].timestamp,
                    user=user if user != "unknown" else None,
                    event_count=len(u_events),
                    summary=f"User '{user}' triggered {len(u_events)} unauthorized/failed sudo event(s).",
                    evidence=[e.raw for e in u_events[:6]],
                )
            )

    # 3. High-risk privileged command execution (sudo / auditd)
    exec_events = [
        e
        for e in sorted_events
        if e.command and e.event_type in {"sudo_exec", "sudo_unauthorized", "auditd_execve", "auditd_user_cmd", "auditd_syscall"}
    ]
    for ev in exec_events:
        cmd = ev.command or ""
        for pattern, desc, techniques, sev in _HIGH_RISK_CMD_PATTERNS:
            if pattern.search(cmd):
                alerts.append(
                    Alert(
                        id=_next_id(counter),
                        detector="rule",
                        rule_id="SUSPICIOUS_PRIV_EXEC",
                        title=f"{desc} (user={ev.user or 'unknown'})",
                        severity=sev,
                        confidence=0.91,
                        mitre_techniques=techniques,
                        start_time=ev.timestamp,
                        end_time=ev.timestamp,
                        src_ip=ev.src_ip,
                        user=ev.user,
                        event_count=1,
                        summary=f"Suspicious command executed via {ev.process}: `{cmd}`",
                        evidence=[ev.raw],
                    )
                )
                break

    # 4. Account creation / persistence
    acct_events: list[LogEvent] = []
    for ev in sorted_events:
        if ev.event_type == "account_change":
            acct_events.append(ev)
        elif ev.command and any(p.search(ev.command) for p in _ACCOUNT_PERSISTENCE_PATTERNS):
            acct_events.append(ev)
    if acct_events:
        for ev in acct_events:
            alerts.append(
                Alert(
                    id=_next_id(counter),
                    detector="rule",
                    rule_id="ACCOUNT_PERSISTENCE",
                    title=f"Account creation or privilege modification ({ev.user or 'unknown'})",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    mitre_techniques=["T1136.001", "T1098"],
                    start_time=ev.timestamp,
                    end_time=ev.timestamp,
                    src_ip=ev.src_ip,
                    user=ev.user,
                    event_count=1,
                    summary=f"Account modification observed: {ev.command or ev.raw}",
                    evidence=[ev.raw],
                )
            )

    # 5. Embedded prompt-injection detection inside untrusted log fields
    injection_hits: list[LogEvent] = []
    for ev in sorted_events:
        candidate = _normalize_for_injection(" ".join(filter(None, [ev.user, ev.command, ev.raw])))
        if any(p.search(candidate) for p in _PROMPT_INJECTION_PATTERNS):
            injection_hits.append(ev)

    if injection_hits:
        first = injection_hits[0]
        alerts.append(
            Alert(
                id=_next_id(counter),
                detector="rule",
                rule_id="LOG_PROMPT_INJECTION",
                title="Prompt injection payload embedded in log telemetry",
                severity=Severity.HIGH,
                confidence=0.95,
                mitre_techniques=["T1562"],
                start_time=injection_hits[0].timestamp,
                end_time=injection_hits[-1].timestamp,
                src_ip=first.src_ip,
                user=first.user,
                event_count=len(injection_hits),
                summary=f"Detected {len(injection_hits)} log event(s) containing prompt-injection instructions aimed at evading triage.",
                evidence=[e.raw for e in injection_hits[:5]],
            )
        )

    return alerts
