"""Local MITRE ATT&CK knowledge base retriever using Ollama embeddings with offline fallback."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import numpy as np
from pydantic import BaseModel, Field

from secguard.config import AppConfig
from secguard.detectors.models import IncidentCluster

_DEFAULT_KB_PATH = Path(__file__).with_name("mitre_kb.json")


class MitreEntry(BaseModel):
    id: str
    name: str
    tactic: str
    description: str
    linux_indicators: list[str] = Field(default_factory=list)
    containment_steps: list[str] = Field(default_factory=list)

    def to_document(self) -> str:
        indicators = "; ".join(self.linux_indicators)
        return f"{self.id} {self.name} ({self.tactic}): {self.description} Indicators: {indicators}"


class MitreRetriever:
    """Retrieves relevant MITRE ATT&CK entries for an incident cluster."""

    def __init__(self, config: AppConfig, kb_path: Path | None = None) -> None:
        self.config = config
        self.kb_path = kb_path or _DEFAULT_KB_PATH
        raw = json.loads(self.kb_path.read_text(encoding="utf-8"))
        self.entries: list[MitreEntry] = [MitreEntry.model_validate(item) for item in raw]
        self._by_id: dict[str, MitreEntry] = {e.id: e for e in self.entries}
        self._embeddings: np.ndarray | None = None

    def _embed_texts(self, texts: list[str]) -> list[list[float]]:
        url = f"{self.config.ollama.base_url.rstrip('/')}/api/embed"
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(
                url,
                json={"model": self.config.ollama.embed_model, "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
            embeddings = data.get("embeddings")
            if not isinstance(embeddings, list) or len(embeddings) != len(texts):
                raise ValueError("Unexpected /api/embed response payload")
            return embeddings

    def _ensure_kb_embeddings(self) -> np.ndarray | None:
        if self._embeddings is not None:
            return self._embeddings

        cache_path = Path(self.config.rag.cache_path)
        if cache_path.exists():
            try:
                cached: dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
                if (
                    cached.get("embed_model") == self.config.ollama.embed_model
                    and cached.get("ids") == [e.id for e in self.entries]
                ):
                    mat = np.array(cached["vectors"], dtype=float)
                    self._embeddings = mat
                    return mat
            except Exception:
                pass

        try:
            docs = [e.to_document() for e in self.entries]
            vectors = self._embed_texts(docs)
            mat = np.array(vectors, dtype=float)
            self._embeddings = mat
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(
                    {
                        "embed_model": self.config.ollama.embed_model,
                        "ids": [e.id for e in self.entries],
                        "vectors": vectors,
                    }
                ),
                encoding="utf-8",
            )
            return mat
        except Exception:
            return None

    def retrieve_for_incident(
        self,
        incident: IncidentCluster,
        use_embeddings: bool = True,
        top_k: int | None = None,
    ) -> list[MitreEntry]:
        """Return exact MITRE ID matches plus top-k semantic or keyword matches."""
        k = top_k or self.config.rag.top_k
        selected: list[MitreEntry] = []
        seen_ids: set[str] = set()

        for tech_id in incident.mitre_techniques:
            if tech_id in self._by_id and tech_id not in seen_ids:
                selected.append(self._by_id[tech_id])
                seen_ids.add(tech_id)

        query_text = " ".join(
            [incident.title]
            + [a.summary for a in incident.alerts]
            + incident.mitre_techniques
        )

        if use_embeddings and self.config.rag.enabled:
            kb_mat = self._ensure_kb_embeddings()
            if kb_mat is not None:
                try:
                    q_vec = np.array(self._embed_texts([query_text])[0], dtype=float)
                    q_norm = np.linalg.norm(q_vec) + 1e-12
                    kb_norms = np.linalg.norm(kb_mat, axis=1) + 1e-12
                    sims = (kb_mat @ q_vec) / (kb_norms * q_norm)
                    ranked_indices = np.argsort(-sims)
                    for idx in ranked_indices:
                        entry = self.entries[int(idx)]
                        if entry.id not in seen_ids:
                            selected.append(entry)
                            seen_ids.add(entry.id)
                        if len(selected) >= k:
                            return selected[:k]
                except Exception:
                    pass

        # Offline keyword fallback
        tokens = set(re.findall(r"[a-z0-9_./-]+", query_text.lower()))
        scored: list[tuple[int, MitreEntry]] = []
        for entry in self.entries:
            if entry.id in seen_ids:
                continue
            doc_tokens = set(re.findall(r"[a-z0-9_./-]+", entry.to_document().lower()))
            overlap = len(tokens & doc_tokens)
            scored.append((overlap, entry))
        scored.sort(key=lambda item: item[0], reverse=True)
        for _, entry in scored:
            if len(selected) >= k:
                break
            selected.append(entry)
            seen_ids.add(entry.id)

        return selected[:k]
