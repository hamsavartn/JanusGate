"""Tamper-evident audit log — hash-chained JSONL.

Each entry carries `seq`, `prev_hash`, and `hash` = SHA-256 over the canonical JSON of
the entry including the previous hash. Any retroactive edit breaks the chain and
`GET /audit/verify` (and evals/verify_system) detects exactly where.

Privacy: with AUDIT_REDACT=1, previews are truncated + hashed so the log proves what was
inspected without storing user content in the clear.
"""
import hashlib
import json
import os
import time
from pathlib import Path

from backend.config import AUDIT_REDACT, ROOT
from backend.schemas import EnsembleVerdict

AUDIT_PATH = Path(os.getenv("SENTINEL_AUDIT_PATH", ROOT / "data" / "audit_log.jsonl"))


def _hash_entry(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _redact(preview: str) -> str:
    if not AUDIT_REDACT or not preview:
        return preview
    h = hashlib.sha256(preview.encode()).hexdigest()[:12]
    return f"{preview[:24]}…#{h}"


def _last_seq_and_hash() -> tuple[int, str]:
    if not AUDIT_PATH.exists():
        return 0, "0" * 64
    last_seq, last_hash = 0, "0" * 64
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0, "0" * 64
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            last_seq, last_hash = int(e.get("seq", 0)), e.get("hash", last_hash)
        except (json.JSONDecodeError, ValueError):
            continue
    return last_seq, last_hash


def _append(entry: dict) -> None:
    try:
        seq, prev = _last_seq_and_hash()
        entry = dict(entry)
        entry.pop("seq", None)
        entry.pop("prev_hash", None)
        entry.pop("hash", None)
        entry["seq"] = seq + 1
        entry["prev_hash"] = prev
        entry["hash"] = _hash_entry({k: v for k, v in entry.items() if k != "hash"})
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # audit must never break inspection


def record(verdict: EnsembleVerdict, source: str) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "type": "ingress",
        "source": source,
        "is_attack": verdict.is_attack,
        "attack_class": verdict.attack_class,
        "final_risk": verdict.final_risk,
        "layers_used": verdict.layers_used,
        "latency_ms": verdict.latency_ms,
        "text_preview": _redact(verdict.text_preview),
        "heuristic_hits": [h.model_dump() for h in verdict.heuristic_hits],
        "llm_verdict": verdict.llm_verdict.model_dump() if verdict.llm_verdict else None,
    }
    _append(entry)


def record_egress(verdict, source: str = "agent_reply") -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "type": "egress",
        "source": source,
        "is_leak": verdict.is_leak,
        "risk": verdict.risk,
        "reasons": verdict.reasons,
        "latency_ms": verdict.latency_ms,
    }
    _append(entry)


def record_feedback(entry: dict) -> None:
    _append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "type": "feedback", **entry})


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


def verify_chain() -> dict:
    """Walk the chain; report the first broken link, if any.

    Entries written before the hash chain existed (no `seq` field) are skipped as
    legacy; the chain is expected to start at the first entry WITH a seq, anchored
    by prev_hash = 0x00…0.
    """
    if not AUDIT_PATH.exists():
        return {"ok": True, "entries": 0, "broken_at": None, "legacy_skipped": 0}
    prev_hash = "0" * 64
    expected_seq = 1
    chained = 0
    legacy = 0
    chain_started = False
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"ok": True, "entries": 0, "broken_at": None, "legacy_skipped": 0}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "entries": chained, "broken_at": expected_seq,
                    "reason": "unparseable line", "legacy_skipped": legacy}
        if "seq" not in e:
            legacy += 1  # pre-chain legacy entry — skip, don't fail
            continue
        if not chain_started:
            chain_started = True
        if e.get("seq") != expected_seq:
            return {"ok": False, "entries": chained, "broken_at": expected_seq,
                    "reason": "sequence gap", "legacy_skipped": legacy}
        if e.get("prev_hash") != prev_hash:
            return {"ok": False, "entries": chained, "broken_at": expected_seq,
                    "reason": "prev_hash mismatch (log was edited or reordered)",
                    "legacy_skipped": legacy}
        recomputed = _hash_entry({k: v for k, v in e.items() if k != "hash"})
        if recomputed != e.get("hash"):
            return {"ok": False, "entries": chained, "broken_at": expected_seq,
                    "reason": "entry hash mismatch (content edited)", "legacy_skipped": legacy}
        prev_hash = e["hash"]
        expected_seq += 1
        chained += 1
    return {"ok": True, "entries": chained, "broken_at": None, "legacy_skipped": legacy}
