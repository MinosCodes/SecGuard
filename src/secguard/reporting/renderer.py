"""Render SecurityReport objects to Markdown, JSON, and standalone HTML."""

from __future__ import annotations

import html
from pathlib import Path

from secguard.llm.triage import SecurityReport


def render_markdown(report: SecurityReport) -> str:
    """Render a SecurityReport as clean GitHub-flavored Markdown."""
    lines: list[str] = [
        f"# SecGuard Security Report ({report.report_id})",
        "",
        f"- **Generated At:** `{report.generated_at.isoformat()}`",
        f"- **Log Source:** `{report.log_source}`",
        f"- **Mode:** `{report.mode}`" + (f" (`{report.model_used}`)" if report.model_used else ""),
        f"- **Overall Risk:** **{report.overall_risk.value}**",
        f"- **Events / Alerts / Incidents:** {report.total_events} / {report.total_alerts} / {len(report.incidents)}",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
    ]

    if not report.incidents:
        lines.extend(["## Incidents", "", "No security incidents detected.", ""])
    else:
        lines.append("## Triaged Incidents")
        lines.append("")
        for inc in report.incidents:
            lines.extend(
                [
                    f"### {inc.incident_id}: {inc.title}",
                    "",
                    f"- **Verdict:** `{inc.verdict}` | **Severity:** **{inc.severity.value}** | **Confidence:** `{inc.confidence:.2f}`",
                    f"- **Timeframe:** `{inc.start_time.isoformat()}` -> `{inc.end_time.isoformat()}`",
                    f"- **MITRE ATT&CK:** {', '.join(f'`{t}`' for t in inc.mitre_techniques) or 'None'}",
                    f"- **Prompt Injection Detected:** `{inc.prompt_injection_detected}`",
                    "",
                    "**Summary:**",
                    inc.executive_summary,
                    "",
                    "**Attack Narrative:**",
                    inc.attack_narrative,
                    "",
                    "**Indicators of Compromise (IOCs):**",
                ]
            )
            if inc.iocs:
                lines.extend(f"- `{ioc}`" for ioc in inc.iocs)
            else:
                lines.append("- None extracted")
            lines.append("")
            lines.append("**Recommended Actions (Human Review Required):**")
            if inc.recommended_actions:
                lines.extend(f"- {act}" for act in inc.recommended_actions)
            else:
                lines.append("- None")
            lines.append("")

    if report.alerts:
        lines.extend(
            [
                "## Raw Detector Alerts",
                "",
                "| ID | Detector | Rule | Severity | Src IP | User | Count | Summary |",
                "|---|---|---|---|---|---|---:|---|",
            ]
        )
        for a in report.alerts:
            safe_summary = a.summary.replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| `{a.id}` | {a.detector} | `{a.rule_id}` | **{a.severity.value}** | "
                f"`{a.src_ip or '-'}` | `{a.user or '-'}` | {a.event_count} | {safe_summary} |"
            )
        lines.append("")

    if report.telemetry:
        lines.extend(
            [
                "## Local LLM Inference Telemetry",
                "",
                "| Model | Duration (s) | Prompt Tokens | Output Tokens | Speed (tok/s) |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for t in report.telemetry:
            lines.append(
                f"| `{t.model}` | {t.duration_s:.2f} | {t.prompt_eval_count} | {t.eval_count} | {t.tokens_per_sec:.2f} |"
            )
        lines.append("")

    return "\n".join(lines)


def render_html(report: SecurityReport) -> str:
    """Render a SecurityReport as a standalone dark-themed HTML report."""
    sev_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
    }
    risk_color = sev_colors.get(report.overall_risk.value, "#64748b")

    inc_cards: list[str] = []
    for inc in report.incidents:
        color = sev_colors.get(inc.severity.value, "#64748b")
        iocs_html = "".join(f"<li><code>{html.escape(i)}</code></li>" for i in inc.iocs) or "<li>None</li>"
        actions_html = "".join(f"<li>{html.escape(a)}</li>" for a in inc.recommended_actions) or "<li>None</li>"
        mitre_html = " ".join(
            f"<span class='tag'>{html.escape(t)}</span>" for t in inc.mitre_techniques
        ) or "<span class='muted'>None</span>"
        inj_badge = (
            "<span class='badge' style='background:#7c3aed'>PROMPT INJECTION DETECTED</span>"
            if inc.prompt_injection_detected
            else ""
        )
        inc_cards.append(
            f"""
            <section class="card">
              <div class="card-header">
                <h3>{html.escape(inc.incident_id)}: {html.escape(inc.title)}</h3>
                <div>
                  <span class="badge" style="background:{color}">{html.escape(inc.severity.value)}</span>
                  <span class="badge" style="background:#334155">{html.escape(inc.verdict)} ({inc.confidence:.2f})</span>
                  {inj_badge}
                </div>
              </div>
              <p class="meta">{html.escape(inc.start_time.isoformat())} &rarr; {html.escape(inc.end_time.isoformat())} | MITRE: {mitre_html}</p>
              <p><strong>Summary:</strong> {html.escape(inc.executive_summary)}</p>
              <p><strong>Narrative:</strong><br/>{html.escape(inc.attack_narrative).replace(chr(10), '<br/>')}</p>
              <div class="grid">
                <div><h4>IOCs</h4><ul>{iocs_html}</ul></div>
                <div><h4>Recommended Actions</h4><ul>{actions_html}</ul></div>
              </div>
            </section>
            """
        )

    incidents_section = "\n".join(inc_cards) if inc_cards else "<p class='muted'>No security incidents detected.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecGuard Report - {html.escape(report.report_id)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; line-height: 1.5; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header {{ border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; color: #fff; margin-left: 0.3rem; }}
    .tag {{ display: inline-block; background: #1e293b; border: 1px solid #475569; padding: 0.1rem 0.45rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.25rem; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }}
    .card-header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }}
    .meta {{ color: #94a3b8; font-size: 0.88rem; }}
    .muted {{ color: #94a3b8; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
    code {{ background: #0f172a; padding: 0.1rem 0.35rem; border-radius: 4px; color: #38bdf8; }}
    @media (max-width: 720px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin:0;">SecGuard Security Report</h1>
        <div class="meta">{html.escape(report.report_id)} | Source: <code>{html.escape(report.log_source)}</code> | Mode: <code>{html.escape(report.mode)}</code> {f"({html.escape(report.model_used)})" if report.model_used else ""}</div>
      </div>
      <span class="badge" style="background:{risk_color}; font-size:1rem; padding:0.4rem 0.9rem;">RISK: {html.escape(report.overall_risk.value)}</span>
    </div>
    <section class="card">
      <h2 style="margin-top:0;">Executive Summary</h2>
      <p>{html.escape(report.executive_summary)}</p>
      <p class="meta">Events: {report.total_events} | Alerts: {report.total_alerts} | Incidents: {len(report.incidents)} | Generated: {html.escape(report.generated_at.isoformat())}</p>
    </section>
    <h2>Triaged Incidents</h2>
    {incidents_section}
  </div>
</body>
</html>
"""


def write_reports(
    report: SecurityReport,
    output_dir: Path,
    fmt: str = "all",
    prefix: str = "secguard_report",
) -> list[Path]:
    """Write report files in the requested format(s): all, md, json, or html."""
    output_dir.mkdir(parents=True, exist_ok=True)
    fmt_norm = fmt.lower()
    formats = ["md", "json", "html"] if fmt_norm == "all" else [fmt_norm]
    written: list[Path] = []

    for ext in formats:
        target = output_dir / f"{prefix}.{ext}"
        if ext == "md":
            target.write_text(render_markdown(report), encoding="utf-8")
        elif ext == "json":
            target.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        elif ext == "html":
            target.write_text(render_html(report), encoding="utf-8")
        else:
            raise ValueError(f"Unsupported report format: {ext}")
        written.append(target)

    return written
