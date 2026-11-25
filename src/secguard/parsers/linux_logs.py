"""Parsers for Linux auth.log, sudo, account management, auditd, and syslog."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from secguard.parsers.models import LogEvent

# Traditional syslog header: "Nov 25 10:15:30 host proc[123]: msg"
_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# ISO-8601 syslog header: "2026-11-25T10:15:30+00:00 host proc[123]: msg"
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# auditd header: "type=EXECVE msg=audit(1732529730.123:456): ..."
_AUDITD_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<atype>[A-Z0-9_]+)\s+"
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$"
)

# IPv4 or IPv6 address (sshd logs both, e.g. "from 2001:db8::1 port 22")
_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})"

_SSH_INVALID_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>" + _IP + r")(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_FAILED_RE = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>" + _IP + r")(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>" + _IP + r")(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_DISCONNECT_RE = re.compile(
    r"(?:Disconnected from|Connection closed by)\s+(?:(?:authenticating|invalid)\s+user\s+)?(?:(?P<user>\S+)\s+)?(?P<ip>" + _IP + r")(?:\s+port\s+(?P<port>\d+))?"
)
_PAM_RHOST_RE = re.compile(r"\brhost=(\S+)")
_PAM_USER_RE = re.compile(r"\buser=(\S+)")
_SUDO_CMD_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*.*?;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
_SUDO_NOT_SUDOERS_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*user NOT in sudoers\s*;.*?(?:COMMAND=(?P<cmd>.+))?$"
)
_SUDO_FAIL_ATTEMPTS_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*(?P<count>\d+)\s+incorrect password attempts"
)
_USERADD_RE = re.compile(r"new user:\s*name=([^,\s]+)")
_USERMOD_RE = re.compile(r"add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'")
_PASSWD_RE = re.compile(r"password changed for\s+(?P<user>\S+)")
_KV_RE = re.compile(r'([A-Za-z0-9_]+)=("[^"]*"|\S+)')

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _maybe_decode_hex(value: str) -> str:
    if len(value) >= 2 and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        try:
            decoded = bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if decoded and all(ch.isprintable() or ch.isspace() for ch in decoded):
                return decoded
        except ValueError:
            pass
    return value


def _parse_kv_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, raw_val in _KV_RE.findall(body):
        val = raw_val[1:-1] if raw_val.startswith('"') and raw_val.endswith('"') else _maybe_decode_hex(raw_val)
        fields[key] = val
    return fields


def _parse_rfc3164_ts(month_str: str, day_str: str, time_str: str, year: int) -> datetime:
    month = _MONTHS[month_str]
    day = int(day_str)
    hh, mm, ss = (int(x) for x in time_str.split(":"))
    return datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)


def _parse_iso_ts(ts_str: str) -> datetime:
    normalized = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_auditd_line(line: str, match: re.Match[str]) -> LogEvent:
    atype = match.group("atype")
    epoch = float(match.group("epoch"))
    ts = datetime.fromtimestamp(epoch, tz=timezone.utc)
    host = match.group("node") or "localhost"
    body = match.group("body")
    fields = _parse_kv_fields(body)

    user = fields.get("acct") or fields.get("uid") or fields.get("auid")
    if user in {"unset", "(unknown)", "?"}:
        user = None
    src_ip = fields.get("addr")
    if src_ip in {"?", "0.0.0.0"}:
        src_ip = None

    command: str | None = None
    if atype == "EXECVE":
        argc = int(fields.get("argc", "0")) if fields.get("argc", "").isdigit() else 0
        args = [fields[f"a{i}"] for i in range(argc) if f"a{i}" in fields]
        if not args:
            args = [fields[k] for k in sorted(fields) if re.fullmatch(r"a\d+", k)]
        command = " ".join(args) if args else None
    else:
        command = fields.get("cmd") or fields.get("exe") or fields.get("comm")

    res = fields.get("res") or fields.get("success") or ""
    if res.lower() in {"success", "yes"}:
        outcome = "success"
    elif res.lower() in {"failed", "no"}:
        outcome = "failure"
    else:
        outcome = "info"

    return LogEvent(
        timestamp=ts,
        host=host,
        source="auditd",
        process="auditd",
        event_type=f"auditd_{atype.lower()}",
        user=user,
        src_ip=src_ip,
        command=command,
        outcome=outcome,
        raw=line,
        metadata={"audit_type": atype, "serial": match.group("serial"), "fields": fields},
    )


def _parse_syslog_line(
    line: str,
    source_hint: str,
    default_year: int,
    infer_year: bool = False,
) -> LogEvent:
    ts: datetime
    host = "unknown"
    proc = "unknown"
    pid: int | None = None
    msg = line

    if iso_m := _ISO_SYSLOG_RE.match(line):
        ts = _parse_iso_ts(iso_m.group("ts"))
        host = iso_m.group("host")
        proc = iso_m.group("proc")
        pid = int(iso_m.group("pid")) if iso_m.group("pid") else None
        msg = iso_m.group("msg")
    elif rfc_m := _RFC3164_RE.match(line):
        ts = _parse_rfc3164_ts(rfc_m.group("month"), rfc_m.group("day"), rfc_m.group("time"), default_year)
        # RFC 3164 headers carry no year. When we guessed "current year", a December line read in
        # January would land in the future, so roll it back one year.
        if infer_year and ts > datetime.now(timezone.utc) + timedelta(days=1):
            try:
                ts = ts.replace(year=ts.year - 1)
            except ValueError:  # Feb 29 in a non-leap year
                ts = ts.replace(year=ts.year - 1, day=28)
        host = rfc_m.group("host")
        proc = rfc_m.group("proc")
        pid = int(rfc_m.group("pid")) if rfc_m.group("pid") else None
        msg = rfc_m.group("msg")
    else:
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source=source_hint if source_hint != "auto" else "syslog",
            event_type="syslog_generic",
            raw=line,
        )

    proc_lower = proc.lower()
    src = source_hint if source_hint != "auto" else ("auth.log" if proc_lower in {"sshd", "sudo", "su", "useradd", "usermod", "passwd"} else "syslog")

    if proc_lower == "sshd":
        if m := _SSH_FAILED_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="ssh_failed_auth",
                user=m.group("user"),
                src_ip=m.group("ip"),
                src_port=int(m.group("port")) if m.group("port") else None,
                outcome="failure",
                raw=line,
                metadata={"auth_method": m.group("method"), "invalid_user": "invalid user" in msg.lower()},
            )
        if m := _SSH_INVALID_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="ssh_invalid_user",
                user=m.group("user"),
                src_ip=m.group("ip"),
                src_port=int(m.group("port")) if m.group("port") else None,
                outcome="failure",
                raw=line,
            )
        if m := _SSH_ACCEPTED_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="ssh_accepted",
                user=m.group("user"),
                src_ip=m.group("ip"),
                src_port=int(m.group("port")) if m.group("port") else None,
                outcome="success",
                raw=line,
                metadata={"auth_method": m.group("method")},
            )
        if m := _SSH_DISCONNECT_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="ssh_disconnect",
                user=m.group("user"),
                src_ip=m.group("ip"),
                src_port=int(m.group("port")) if m.group("port") else None,
                outcome="info",
                raw=line,
            )
        if "authentication failure" in msg.lower():
            ip_m = _PAM_RHOST_RE.search(msg)
            user_m = _PAM_USER_RE.search(msg)
            ip = ip_m.group(1) if ip_m else None
            user = user_m.group(1) if user_m else None
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="ssh_pam_failure",
                user=user,
                src_ip=ip,
                outcome="failure",
                raw=line,
            )

    if proc_lower == "sudo":
        if m := _SUDO_NOT_SUDOERS_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="sudo_unauthorized",
                user=m.group("user"),
                command=m.group("cmd").strip() if m.group("cmd") else None,
                outcome="failure",
                raw=line,
            )
        if m := _SUDO_FAIL_ATTEMPTS_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="sudo_auth_failure",
                user=m.group("user"),
                outcome="failure",
                raw=line,
                metadata={"attempts": int(m.group("count"))},
            )
        if m := _SUDO_CMD_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                host=host,
                source=src,
                process=proc,
                pid=pid,
                event_type="sudo_exec",
                user=m.group("user"),
                command=m.group("cmd").strip(),
                outcome="success",
                raw=line,
                metadata={"target_user": m.group("target")},
            )

    if proc_lower in {"useradd", "usermod", "passwd", "groupadd"}:
        user: str | None = None
        if m := _USERADD_RE.search(msg):
            user = m.group(1)
        elif m := _USERMOD_RE.search(msg):
            user = m.group("user")
        elif m := _PASSWD_RE.search(msg):
            user = m.group("user")
        return LogEvent(
            timestamp=ts,
            host=host,
            source=src,
            process=proc,
            pid=pid,
            event_type="account_change",
            user=user,
            command=f"{proc_lower}: {msg}",
            outcome="success",
            raw=line,
        )

    return LogEvent(
        timestamp=ts,
        host=host,
        source=src,
        process=proc,
        pid=pid,
        event_type="syslog_generic",
        raw=line,
    )


def parse_log_lines(
    lines: Iterable[str],
    source: str = "auto",
    default_year: int | None = None,
) -> list[LogEvent]:
    """Parse an iterable of Linux log lines into normalized LogEvent objects."""
    infer_year = default_year is None
    year = default_year or datetime.now(timezone.utc).year
    events: list[LogEvent] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if audit_m := _AUDITD_RE.match(line):
            events.append(_parse_auditd_line(line, audit_m))
        else:
            events.append(_parse_syslog_line(line, source_hint=source, default_year=year, infer_year=infer_year))
    return events


def parse_log_file(
    path: Path,
    source: str = "auto",
    default_year: int | None = None,
) -> list[LogEvent]:
    """Read and parse a Linux log file using UTF-8."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return parse_log_lines(fh, source=source, default_year=default_year)
