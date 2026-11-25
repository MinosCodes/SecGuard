"""Prompt-injection defense and sanitization for untrusted log lines."""

from __future__ import annotations

import re
import secrets

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_log_line(line: str, max_chars: int = 240) -> str:
    """Strip ANSI/control characters and bound line length before LLM prompt insertion."""
    cleaned = _ANSI_RE.sub("", line)
    cleaned = _CONTROL_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_chars:
        return cleaned[: max_chars - 3] + "..."
    return cleaned


def wrap_untrusted_evidence(
    lines: list[str],
    max_lines: int = 25,
    max_chars: int = 240,
) -> tuple[str, str]:
    """Sanitize and wrap untrusted log evidence in randomized nonce delimiters."""
    nonce = secrets.token_hex(6)
    sanitized = [sanitize_log_line(line, max_chars=max_chars) for line in lines[:max_lines]]
    body = "\n".join(sanitized) if sanitized else "(no log lines)"
    wrapped = (
        f"<<<UNTRUSTED_LOG_EVIDENCE_{nonce}>>>\n"
        f"{body}\n"
        f"<<<END_UNTRUSTED_LOG_EVIDENCE_{nonce}>>>"
    )
    return wrapped, nonce
