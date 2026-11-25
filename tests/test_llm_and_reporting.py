"""Tests for log sanitization, mocked Ollama JSON retry, RAG fallback, and report rendering."""

from pathlib import Path

from secguard.config import AppConfig
from secguard.llm.ollama_client import OllamaClient, extract_json_object
from secguard.llm.sanitizer import sanitize_log_line, wrap_untrusted_evidence
from secguard.llm.triage import analyze_log_file
from secguard.reporting import render_html, render_markdown, write_reports


def test_sanitizer_strips_ansi_truncates_and_wraps_nonce() -> None:
    dirty = "\x1b[31mALERT\x1b[0m\x07 " + ("A" * 300)
    cleaned = sanitize_log_line(dirty, max_chars=50)
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert len(cleaned) == 50
    assert cleaned.endswith("...")

    wrapped, nonce = wrap_untrusted_evidence([dirty], max_lines=5, max_chars=80)
    assert f"<<<UNTRUSTED_LOG_EVIDENCE_{nonce}>>>" in wrapped
    assert f"<<<END_UNTRUSTED_LOG_EVIDENCE_{nonce}>>>" in wrapped


def test_extract_json_object_handles_fences() -> None:
    text = 'Here is the result:\n```json\n{"verdict": "TRUE_POSITIVE", "confidence": 0.9}\n```'
    parsed = extract_json_object(text)
    assert parsed["verdict"] == "TRUE_POSITIVE"


def test_mocked_ollama_retry_and_triage(tmp_path: Path, monkeypatch) -> None:
    cfg = AppConfig()
    cfg.rag.enabled = False
    client = OllamaClient(cfg.ollama)

    responses = iter(
        [
            "not valid json at all",
            (
                '{"verdict": "TRUE_POSITIVE", "severity": "CRITICAL", "confidence": 0.96, '
                '"executive_summary": "SSH brute force succeeded and attacker escalated.", '
                '"attack_narrative": "Brute force followed by shadow dump and curl|bash.", '
                '"mitre_techniques": ["T1110.001", "T1078"], '
                '"iocs": ["IP: 185.220.101.42"], '
                '"recommended_actions": ["Block 185.220.101.42"], '
                '"prompt_injection_detected": false}'
            ),
            (
                '{"verdict": "TRUE_POSITIVE", "severity": "HIGH", "confidence": 0.92, '
                '"executive_summary": "Prompt injection detected in SSH username.", '
                '"attack_narrative": "Attacker sent injection payload in username.", '
                '"mitre_techniques": ["T1562"], '
                '"iocs": ["IP: 203.0.113.55"], '
                '"recommended_actions": ["Block 203.0.113.55"], '
                '"prompt_injection_detected": true}'
            ),
        ]
    )

    def fake_chat(messages, model=None, format_json=True, keep_alive=None):
        from secguard.llm.ollama_client import OllamaTelemetry

        return next(responses), OllamaTelemetry(
            model=model or cfg.ollama.model,
            duration_s=0.5,
            prompt_eval_count=100,
            eval_count=50,
            tokens_per_sec=100.0,
        )

    monkeypatch.setattr(client, "chat", fake_chat)

    report = analyze_log_file(
        Path("samples/linux_attack_scenario.log"),
        config=cfg,
        use_llm=True,
        use_rag=False,
        client=client,
    )
    assert report.overall_risk.value == "CRITICAL"
    assert len(report.incidents) >= 1
    assert any(i.prompt_injection_detected for i in report.incidents)

    md = render_markdown(report)
    html_doc = render_html(report)
    assert "SecGuard Security Report" in md
    assert "CRITICAL" in html_doc

    written = write_reports(report, output_dir=tmp_path, fmt="all")
    assert len(written) == 3
    assert all(p.exists() for p in written)


def test_rules_only_report_on_benign_baseline(tmp_path: Path) -> None:
    cfg = AppConfig()
    report = analyze_log_file(
        Path("samples/linux_benign_baseline.log"),
        config=cfg,
        use_llm=False,
        use_rag=False,
    )
    assert report.overall_risk.value == "LOW"
    assert report.total_alerts == 0
    written = write_reports(report, output_dir=tmp_path, fmt="all")
    assert len(written) == 3


def test_ollama_chat_think_false_and_400_fallback(monkeypatch) -> None:
    import httpx

    cfg = AppConfig()
    cfg.ollama.disable_thinking = True
    client = OllamaClient(cfg.ollama)
    seen_payloads: list[dict] = []

    class FakeResp:
        def __init__(self, status_code: int, body: dict) -> None:
            self.status_code = status_code
            self._body = body

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
                resp = httpx.Response(self.status_code, request=req)
                raise httpx.HTTPStatusError("err", request=req, response=resp)

        def json(self) -> dict:
            return self._body

    class FakeHttpClient:
        def __init__(self, timeout: float) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            pass

        def post(self, url: str, json: dict) -> FakeResp:
            seen_payloads.append(dict(json))
            if "think" in json:
                return FakeResp(400, {"error": "unknown field think"})
            return FakeResp(
                200,
                {
                    "message": {"content": '{"status": "ok"}'},
                    "prompt_eval_count": 10,
                    "eval_count": 5,
                    "eval_duration": 100_000_000,
                },
            )

    monkeypatch.setattr(httpx, "Client", FakeHttpClient)
    content, tel = client.chat([{"role": "user", "content": "hi"}], format_json=True)
    assert content == '{"status": "ok"}'
    assert tel.tokens_per_sec == 50.0
    assert len(seen_payloads) == 2
    assert seen_payloads[0].get("think") is False
    assert "think" not in seen_payloads[1]
