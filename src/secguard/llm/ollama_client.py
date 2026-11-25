"""HTTP client for local Ollama inference and structured JSON extraction."""

from __future__ import annotations

import json
import re
import time
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from secguard.config import OllamaConfig

T = TypeVar("T", bound=BaseModel)

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


class OllamaTelemetry(BaseModel):
    model: str
    duration_s: float
    prompt_eval_count: int = 0
    eval_count: int = 0
    tokens_per_sec: float = 0.0


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract a JSON object from raw model output, handling markdown fences or surrounding prose."""
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    if m := _FENCE_RE.search(stripped):
        parsed = json.loads(m.group(1))
        if isinstance(parsed, dict):
            return parsed

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        candidate = stripped[start : end + 1]
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed

    raise ValueError(f"Could not extract JSON object from model output: {stripped[:200]}")


class OllamaClient:
    """Synchronous client for local Ollama REST API (/api/tags, /api/chat)."""

    def __init__(self, config: OllamaConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/")

    def list_models(self) -> list[dict[str, Any]]:
        """List locally installed models from Ollama."""
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = data.get("models", [])
            return models if isinstance(models, list) else []

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        format_json: bool = True,
        keep_alive: str | None = None,
    ) -> tuple[str, OllamaTelemetry]:
        """Run a non-streaming chat completion against Ollama."""
        chosen_model = model or self.config.model
        payload: dict[str, Any] = {
            "model": chosen_model,
            "messages": messages,
            "stream": False,
            "keep_alive": keep_alive if keep_alive is not None else self.config.keep_alive,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
                "num_predict": self.config.num_predict,
            },
        }
        if format_json:
            payload["format"] = "json"
        if self.config.disable_thinking:
            payload["think"] = False

        t0 = time.perf_counter()
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(f"{self.base_url}/api/chat", json=payload)
            if resp.status_code == 400 and "think" in payload:
                fallback_payload = dict(payload)
                fallback_payload.pop("think", None)
                resp = client.post(f"{self.base_url}/api/chat", json=fallback_payload)
            resp.raise_for_status()
            data = resp.json()
        wall_s = time.perf_counter() - t0

        content = str(data.get("message", {}).get("content", ""))
        prompt_eval = int(data.get("prompt_eval_count") or 0)
        eval_count = int(data.get("eval_count") or 0)
        eval_ns = int(data.get("eval_duration") or 0)
        if eval_count > 0 and eval_ns > 0:
            tps = eval_count / (eval_ns / 1_000_000_000)
        elif eval_count > 0 and wall_s > 0:
            tps = eval_count / wall_s
        else:
            tps = 0.0

        telemetry = OllamaTelemetry(
            model=chosen_model,
            duration_s=round(wall_s, 3),
            prompt_eval_count=prompt_eval,
            eval_count=eval_count,
            tokens_per_sec=round(tps, 2),
        )
        return content, telemetry

    def chat_structured(
        self,
        messages: list[dict[str, str]],
        schema: type[T],
        model: str | None = None,
        keep_alive: str | None = None,
    ) -> tuple[T, OllamaTelemetry]:
        """Request JSON matching a Pydantic schema with 1 automatic validation retry."""
        convo = list(messages)
        last_error: Exception | None = None
        total_duration = 0.0
        total_prompt = 0
        total_eval = 0
        chosen_model = model or self.config.model

        for attempt in range(2):
            raw_text, tel = self.chat(
                convo,
                model=chosen_model,
                format_json=True,
                keep_alive=keep_alive,
            )
            total_duration += tel.duration_s
            total_prompt += tel.prompt_eval_count
            total_eval += tel.eval_count
            try:
                obj = extract_json_object(raw_text)
                validated = schema.model_validate(obj)
                combined_tel = OllamaTelemetry(
                    model=chosen_model,
                    duration_s=round(total_duration, 3),
                    prompt_eval_count=total_prompt,
                    eval_count=total_eval,
                    tokens_per_sec=tel.tokens_per_sec,
                )
                return validated, combined_tel
            except (ValueError, ValidationError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt == 0:
                    convo.append({"role": "assistant", "content": raw_text})
                    convo.append(
                        {
                            "role": "user",
                            "content": (
                                f"Your JSON output failed schema validation: {exc}. "
                                "Return ONLY a single valid JSON object matching the exact required keys and types."
                            ),
                        }
                    )

        raise ValueError(f"Structured JSON output failed after retry: {last_error}")
