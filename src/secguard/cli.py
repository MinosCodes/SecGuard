"""CLI entrypoint for SecGuard LLM."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Literal, Optional

import typer
import uvicorn
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from secguard.agents import (
    AgentRunState,
    MultiAgentOrchestrator,
    bootstrap_hermes_profiles,
    list_installed_hermes_profiles,
    load_blueprints,
)
from secguard.config import AppConfig, load_config
from secguard.llm.ollama_client import OllamaClient
from secguard.llm.triage import analyze_events, analyze_log_file
from secguard.parsers.linux_logs import parse_log_lines
from secguard.reporting.renderer import write_reports
from secguard.ui import create_app

app = typer.Typer(
    name="secguard",
    help="Hybrid cybersecurity detection, local LLM triage, and report generation for Linux logs.",
    no_args_is_help=True,
)
agents_app = typer.Typer(name="agents", help="Manage and run Hermes-wrapped SecGuard agents.")
app.add_typer(agents_app, name="agents")
console = Console()


def _load_cfg(config_path: Optional[Path]) -> AppConfig:
    return load_config(config_path)


@app.command()
def models(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """List locally available Ollama models and verify connectivity."""
    cfg = _load_cfg(config)
    client = OllamaClient(cfg.ollama)
    try:
        items = client.list_models()
    except Exception as exc:
        console.print(f"[red]Failed to connect to Ollama at {cfg.ollama.base_url}:[/red] {exc}")
        raise typer.Exit(code=1)

    table = Table(title=f"Local Ollama Models ({cfg.ollama.base_url})")
    table.add_column("Model", style="cyan")
    table.add_column("Size (GB)", justify="right")
    table.add_column("Default", justify="center")

    for m in items:
        name = str(m.get("name", ""))
        size_gb = round(float(m.get("size", 0)) / (1024**3), 2)
        is_def = "*" if name == cfg.ollama.model else ""
        table.add_row(name, f"{size_gb:.2f}", is_def)

    console.print(table)


@app.command()
def analyze(
    log_path: Path = typer.Argument(..., exists=True, readable=True, help="Path to Linux log file"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override Ollama model name"),
    output_dir: Path = typer.Option(Path("reports"), "--output-dir", "-o", help="Directory for output reports"),
    fmt: str = typer.Option("all", "--format", "-f", help="Output format: all, md, json, or html"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Run deterministic rules + ML anomaly detection only"),
    no_rag: bool = typer.Option(False, "--no-rag", help="Disable MITRE ATT&CK embedding lookup"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Analyze a Linux log file and generate security reports."""
    cfg = _load_cfg(config)
    report = analyze_log_file(
        log_path=log_path,
        config=cfg,
        use_llm=not no_llm,
        use_rag=not no_rag,
        model_override=model,
    )
    written = write_reports(report, output_dir=output_dir, fmt=fmt)

    console.print(f"[bold]Report ID:[/bold] {report.report_id}")
    console.print(f"[bold]Overall Risk:[/bold] {report.overall_risk.value}")
    console.print(
        f"[bold]Events:[/bold] {report.total_events} | "
        f"[bold]Alerts:[/bold] {report.total_alerts} | "
        f"[bold]Incidents:[/bold] {len(report.incidents)}"
    )
    console.print(f"[bold]Summary:[/bold] {report.executive_summary}")
    for path in written:
        console.print(f"  -> Wrote [green]{path}[/green]")


@app.command()
def benchmark(
    log_path: Path = typer.Argument(..., exists=True, readable=True, help="Path to Linux log file"),
    models_csv: Optional[str] = typer.Option(
        None,
        "--models",
        help="Comma-separated list of Ollama models to benchmark",
    ),
    output_dir: Path = typer.Option(Path("reports/benchmarks"), "--output-dir", "-o", help="Output directory"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Benchmark multiple local Ollama models side-by-side on the same log file."""
    cfg = _load_cfg(config)
    model_list = (
        [m.strip() for m in models_csv.split(",") if m.strip()]
        if models_csv
        else cfg.ollama.benchmark_models
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []

    table = Table(title=f"SecGuard Local LLM Benchmark ({log_path.name})")
    table.add_column("Model", style="cyan")
    table.add_column("JSON Valid", justify="center")
    table.add_column("Risk")
    table.add_column("Verdicts")
    table.add_column("Inj Caught", justify="center")
    table.add_column("Duration (s)", justify="right")
    table.add_column("Speed (tok/s)", justify="right")

    for model_name in model_list:
        safe_slug = model_name.replace("/", "_").replace(":", "_")
        try:
            report = analyze_log_file(
                log_path=log_path,
                config=cfg,
                use_llm=True,
                use_rag=True,
                model_override=model_name,
                keep_alive="0s",
            )
            write_reports(report, output_dir=output_dir, fmt="all", prefix=f"report_{safe_slug}")
            total_dur = sum(t.duration_s for t in report.telemetry)
            total_tok = sum(t.eval_count for t in report.telemetry)
            avg_tps = round(total_tok / total_dur, 2) if total_dur > 0 else 0.0
            verdicts = ", ".join(f"{i.incident_id}:{i.verdict}" for i in report.incidents) or "NONE"
            inj_caught = any(i.prompt_injection_detected for i in report.incidents)
            row = {
                "model": model_name,
                "json_valid": True,
                "overall_risk": report.overall_risk.value,
                "verdicts": verdicts,
                "prompt_injection_caught": inj_caught,
                "duration_s": round(total_dur, 2),
                "tokens_per_sec": avg_tps,
                "error": None,
            }
            table.add_row(
                model_name,
                "YES",
                report.overall_risk.value,
                verdicts,
                "YES" if inj_caught else "NO",
                f"{total_dur:.2f}",
                f"{avg_tps:.2f}",
            )
        except Exception as exc:
            row = {
                "model": model_name,
                "json_valid": False,
                "overall_risk": "ERROR",
                "verdicts": "ERROR",
                "prompt_injection_caught": False,
                "duration_s": 0.0,
                "tokens_per_sec": 0.0,
                "error": str(exc),
            }
            table.add_row(model_name, "NO", "ERROR", str(exc)[:40], "-", "-", "-")
        rows.append(row)

    console.print(table)

    md_lines = [
        f"# SecGuard Model Benchmark ({log_path.name})",
        "",
        "| Model | JSON Valid | Overall Risk | Verdicts | Injection Caught | Duration (s) | Speed (tok/s) |",
        "|---|---|---|---|---|---:|---:|",
    ]
    for r in rows:
        md_lines.append(
            f"| `{r['model']}` | {r['json_valid']} | {r['overall_risk']} | {r['verdicts']} | "
            f"{r['prompt_injection_caught']} | {r['duration_s']} | {r['tokens_per_sec']} |"
        )
    summary_md = output_dir / "benchmark_summary.md"
    summary_json = output_dir / "benchmark_summary.json"
    summary_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    summary_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    console.print(f"Benchmark summary saved to [green]{summary_md}[/green]")


@app.command()
def watch(
    log_path: Path = typer.Argument(..., exists=True, readable=True, help="Linux log file to tail"),
    interval: int = typer.Option(10, "--interval", "-i", help="Polling interval in seconds"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override Ollama model name"),
    output_dir: Path = typer.Option(Path("reports/watch"), "--output-dir", "-o", help="Directory for incident reports"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Run rules/anomaly detection only"),
    once: bool = typer.Option(False, "--once", help="Process existing content once and exit"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Continuously watch a Linux log file (handling log rotation) and generate reports on new alerts."""
    cfg = _load_cfg(config)
    offset = 0 if once else log_path.stat().st_size
    console.print(f"Watching [cyan]{log_path}[/cyan] every {interval}s (offset={offset})...")

    while True:
        try:
            size = log_path.stat().st_size
            if size < offset:
                console.print("[yellow]Detected log rotation/truncation; resetting offset to 0.[/yellow]")
                offset = 0
            if size > offset:
                with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    offset = fh.tell()
                lines = [ln for ln in chunk.splitlines() if ln.strip()]
                if lines:
                    events = parse_log_lines(lines)
                    report = analyze_events(
                        events=events,
                        config=cfg,
                        log_source=str(log_path),
                        use_llm=not no_llm,
                        model_override=model,
                    )
                    if report.total_alerts > 0:
                        prefix = f"watch_{report.report_id.lower()}"
                        written = write_reports(report, output_dir=output_dir, fmt="all", prefix=prefix)
                        console.print(
                            f"[red][ALERT][/red] {report.overall_risk.value}: {report.total_alerts} alert(s) -> {written[0]}"
                        )
        except KeyboardInterrupt:
            console.print("Stopping watcher.")
            break

        if once:
            break
        time.sleep(interval)


def _render_live_dashboard(state: AgentRunState) -> Layout:
    """Build a Rich Live terminal layout showing agents, tasks, and recent events."""
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=9),
        Layout(name="middle", size=11),
        Layout(name="bottom", size=9),
    )

    ag_table = Table(title=f"Hermes Agents ({state.run_id} | {state.backend}:{state.model})", expand=True)
    ag_table.add_column("Agent", style="cyan")
    ag_table.add_column("Role")
    ag_table.add_column("Status")
    ag_table.add_column("Session")
    ag_table.add_column("Tokens (in/out)", justify="right")

    for ag in state.agents.values():
        st_color = {"idle": "dim", "running": "cyan", "completed": "green", "error": "red"}.get(ag.status, "white")
        ag_table.add_row(
            ag.name,
            ag.role,
            f"[{st_color}]{ag.status.upper()}[/{st_color}]",
            ag.session_id or "-",
            f"{ag.input_tokens}/{ag.output_tokens}",
        )
    layout["top"].update(ag_table)

    t_table = Table(title="Live Task Board", expand=True)
    t_table.add_column("ID", style="bold")
    t_table.add_column("Agent")
    t_table.add_column("Task")
    t_table.add_column("Status")
    t_table.add_column("Summary")

    for t in state.tasks:
        tc = {
            "queued": "dim",
            "in_progress": "cyan",
            "completed": "green",
            "skipped": "yellow",
            "failed": "red",
        }.get(t.status, "white")
        t_table.add_row(t.id, t.agent, t.title, f"[{tc}]{t.status}[/{tc}]", (t.summary or t.description)[:70])
    layout["middle"].update(t_table)

    ev_lines = [f"[{e.timestamp.strftime('%H:%M:%S')}] {e.agent}: {e.message}" for e in state.events[-5:]]
    layout["bottom"].update(Panel("\n".join(ev_lines) or "Starting...", title="Hermes Stream Events"))
    return layout


@agents_app.command("init")
def agents_init(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Ollama model for Hermes profiles"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Create and configure the 4 SecGuard Hermes agent profiles wrapped around Ollama."""
    cfg = _load_cfg(config)
    results = bootstrap_hermes_profiles(cfg, model_override=model)
    table = Table(title="SecGuard Hermes Agent Profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Role")
    table.add_column("Status")
    table.add_column("Model")
    table.add_column("Directory")
    for row in results:
        table.add_row(row["name"], row["role"], row["status"], row["model"], row["path"])
    console.print(table)


@agents_app.command("list")
def agents_list(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """List SecGuard agent blueprints and their local Hermes profile installation status."""
    cfg = _load_cfg(config)
    installed = list_installed_hermes_profiles(cfg.hermes.executable)
    table = Table(title="SecGuard Agent Blueprints")
    table.add_column("Agent", style="cyan")
    table.add_column("Role")
    table.add_column("Uses LLM", justify="center")
    table.add_column("Hermes Profile", justify="center")
    for bp in load_blueprints():
        table.add_row(
            bp.name,
            bp.role,
            "YES" if bp.uses_llm else "NO",
            "INSTALLED" if bp.name in installed else "NOT INIT",
        )
    console.print(table)


@agents_app.command("run")
def agents_run(
    log_path: Path = typer.Argument(..., exists=True, readable=True, help="Linux log file to analyze"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override Ollama model"),
    backend: Literal["hermes", "ollama"] = typer.Option("hermes", "--backend", "-b", help="hermes or ollama"),
    output_dir: Path = typer.Option(Path("reports/agents"), "--output-dir", "-o", help="Report output directory"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Run the 4-agent Hermes SOC workflow with a live terminal task visualizer."""
    cfg = _load_cfg(config)
    chosen_model = model or (cfg.hermes.model if backend == "hermes" else cfg.ollama.model)

    with Live(console=console, refresh_per_second=4) as live:
        def _on_update(st: AgentRunState, _ev) -> None:
            live.update(_render_live_dashboard(st))

        orch = MultiAgentOrchestrator(config=cfg, on_update=_on_update)
        final_state = orch.run(
            log_path=log_path,
            output_dir=output_dir,
            model_override=chosen_model,
            backend=backend,
        )
        live.update(_render_live_dashboard(final_state))

    console.print(
        f"\n[bold]Run:[/bold] {final_state.run_id} | [bold]Risk:[/bold] {final_state.overall_risk} | "
        f"[bold]Verdict:[/bold] {final_state.verdict} | [bold]Injection Caught:[/bold] {final_state.prompt_injection_detected}"
    )
    for fmt_name, fpath in final_state.report_files.items():
        console.print(f"  -> {fmt_name.upper()}: [green]{fpath}[/green]")


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8765, "--port", help="Bind port"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Launch the real-time Web UI visualizing Hermes agents, tasks, and Ollama streams."""
    cfg = _load_cfg(config)
    web_app = create_app(cfg)
    console.print(f"Starting SecGuard Hermes Visualizer at [cyan]http://{host}:{port}[/cyan]")
    uvicorn.run(web_app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
