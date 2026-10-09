"""Append-only audit log. One JSON line per inspection, queryable for the dashboard.

Path is overridable via SENTINEL_AUDIT_PATH (tests use a tmp file so runs stay clean).
"""
import json
import os
import time
from pathlib import Path

from backend.config import ROOT
from backend.schemas import EnsembleVerdict

AUDIT_PATH = Path(os.getenv("SENTINEL_AUDIT_PATH", ROOT / "data" / "audit_log.jsonl"))


def record(verdict: EnsembleVerdict, source: str) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": source,
        "is_attack": verdict.is_attack,
        "attack_class": verdict.attack_class,
        "final_risk": verdict.final_risk,
        "layers_used": verdict.layers_used,
        "latency_ms": verdict.latency_ms,
        "text_preview": verdict.text_preview,
        "heuristic_hits": [h.model_dump() for h in verdict.heuristic_hits],
        "llm_verdict": verdict.llm_verdict.model_dump() if verdict.llm_verdict else None,
    }
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # audit must never break inspection


def query(limit: int = 50, only_attacks: bool = False) -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    entries: list[dict] = []
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if only_attacks and not entry.get("is_attack"):
            continue
        entries.append(entry)
    return list(reversed(entries))[:limit]
