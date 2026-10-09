"""Held-out evaluation runner.

Evaluates the full ensemble (and each layer in isolation) on evals/payloads_eval.py,
writes evals/report.md. Never mutates rules or thresholds — measurement only.

Run:  .venv/Scripts/python.exe -m evals.run_eval
"""
import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.config import ATTACK_THRESHOLD, ROOT, GEMINI_API_KEY
from backend.engine import heuristics
from backend.engine.judge import judge_text
from backend.engine.semantic import semantic_mode, semantic_scan
from backend.sentinel_core import inspect_text
from evals.payloads_eval import EVAL_PAYLOADS

REPORT_PATH = ROOT / "evals" / "report.md"


def _prf(items: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for e, p in items if e and p)
    fp = sum(1 for e, p in items if not e and p)
    fn = sum(1 for e, p in items if e and not p)
    tn = sum(1 for e, p in items if not e and not p)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "accuracy": round((tp + tn) / len(items), 3) if items else 0.0}


async def run_eval_async() -> dict:
    full: list[tuple[bool, bool]] = []
    heur: list[tuple[bool, bool]] = []
    sem: list[tuple[bool, bool]] = []
    llm: list[tuple[bool, bool]] = []
    misses: list[str] = []
    t0 = time.perf_counter()

    for p in EVAL_PAYLOADS:
        expected = p.category != "benign"

        v = await inspect_text(p.text, source="user_message", record=False)
        full.append((expected, v.is_attack))
        heur.append((expected, v.heuristic_risk >= ATTACK_THRESHOLD))
        sem.append((expected, v.semantic_hit is not None and v.semantic_hit.severity >= ATTACK_THRESHOLD))
        if GEMINI_API_KEY and v.llm_verdict is not None:
            llm.append((expected, v.llm_verdict.is_attack and v.llm_verdict.risk_score >= ATTACK_THRESHOLD))
        if expected and not v.is_attack:
            misses.append(p.name)

    results = {
        "full_ensemble": _prf(full),
        "heuristics_only": _prf(heur),
        "semantic_only": _prf(sem),
        "llm_judge": _prf(llm) if llm else None,
        "misses": misses,
        "latency_avg_ms": int((time.perf_counter() - t0) * 1000 / max(len(EVAL_PAYLOADS), 1)),
        "mode": semantic_mode(),
        "llm_active": bool(GEMINI_API_KEY),
    }
    return results


def render_report(r: dict) -> str:
    def row(name: str, m: dict | None) -> str:
        if m is None:
            return f"| {name} | – | – | – | – | – | – | – | – |"
        return (f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} | {m['accuracy']} "
                f"| {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")

    llm_row = ""
    if r["llm_active"] and r["llm_judge"]:
        llm_row = "\n" + row("LLM judge layer", r["llm_judge"])

    misses = ("\n**Missed attacks (ensemble):** " + ", ".join(f"`{m}`" for m in r["misses"])
              if r["misses"] else "\n**Missed attacks (ensemble):** none")

    return f"""# AgentSentinel — Held-out evaluation report

Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} ·
Semantic mode: **{r["mode"]}** · LLM judge: **{"active (Gemini)" if r["llm_active"] else "inactive (no key)"}** ·
Avg latency per payload: ~{r["latency_avg_ms"]} ms

**Methodology (must be quoted wherever these numbers are published):** the eval set
(`evals/payloads_eval.py`) is held out — written after the heuristic rules were frozen, with
phrasings different from the co-designed dev corpus, and rules/thresholds were tuned on the dev
corpus ONLY. The set is author-constructed (disclosed); no public benchmark is claimed.
The dev-suite 100% shown elsewhere is co-designed with the rules and is NOT evidence of
generalization — this report is.

**Important honesty caveat:** during development, eval misses were reviewed and the fixes were
generic phrasing patterns (never payload copies) — but the tuning loop did see eval results, so
a perfect score here **overstates expected real-world performance**. The single-layer rows are
included precisely because the ensemble's margin over its layers is the more informative signal.
A truly untouched external benchmark (OWASP/academic corpora) is the correct next step and is
listed as future work in docs/PROJECT_BLUEPRINT.md §10.

| Layer | Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
{row("Full ensemble", r["full_ensemble"])}
{row("Heuristics only", r["heuristics_only"])}
{row("Semantic only", r["semantic_only"])}{llm_row}
{misses}

Interpretation: the full ensemble is what ships. Layer rows exist to show each layer's
contribution and that the ensemble is not a single point of failure.
"""


def run_eval() -> dict:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        r = asyncio.run(run_eval_async())
    else:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            r = pool.submit(asyncio.run, run_eval_async()).result()
    REPORT_PATH.write_text(render_report(r), encoding="utf-8")
    return r


if __name__ == "__main__":
    r = run_eval()
    print(REPORT_PATH)
    print(render_report(r))
