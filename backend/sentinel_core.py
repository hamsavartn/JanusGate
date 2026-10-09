"""Sentinel Core — merges detection layers into one ensemble verdict.

Layers:
  1. heuristics   (always on, deterministic)
  2. semantic     (corpus similarity — Gemini embeddings online, TF-IDF offline)
  3. LLM judge    (Gemini structured output — active when GEMINI_API_KEY is set)

Merge policy: fail-closed on the strongest signal — the verdict is an attack if any
layer reports an attack at/above threshold; final risk is the max across layers;
attack class comes from the highest-risk layer.
"""
import time

from backend.config import ATTACK_THRESHOLD
from backend.engine import heuristics
from backend.engine.judge import judge_text
from backend.engine.semantic import semantic_scan
from backend.schemas import AttackClass, EnsembleVerdict

# Similarity at which an uncorroborated semantic hit may declare an attack by itself.
SEMANTIC_ALONE_SIMILARITY = 0.70

# Maps heuristic/semantic categories onto the shared AttackClass vocabulary
_CATEGORY_TO_CLASS: dict[str, AttackClass] = {
    "injection": "direct_injection",
    "jailbreak": "jailbreak",
    "tool_hijack": "tool_hijack",
    "exfiltration": "exfiltration",
    "phishing": "phishing",
}


async def inspect_text(text: str, source: str = "user_message", record: bool = True) -> EnsembleVerdict:
    t0 = time.perf_counter()

    hits = heuristics.scan(text)
    h_risk = heuristics.heuristic_risk(hits)

    sem_hit = semantic_scan(text)

    llm_verdict = judge_text(text, source)

    layers = ["heuristics"]
    if sem_hit is not None:
        layers.append("semantic")
    if llm_verdict is not None:
        layers.append("llm_judge")

    # --- ensemble merge: collect (risk, class) candidates from each firing layer ---
    # Corroboration principle: a semantic-only hit declares an attack when similarity is
    # high-confidence (>= SEMANTIC_ALONE_SIMILARITY) or another layer corroborates it.
    # Lower-similarity semantic hits are still reported, but not enough on their own —
    # TF-IDF lexical overlap otherwise flags benign texts (e.g. "what does 'developer
    # mode' mean?"). Boundary set a priori, tuned only against the dev corpus.
    candidates: list[tuple[int, AttackClass]] = []
    if hits:
        top_hit = max(hits, key=lambda h: h.severity)
        candidates.append((h_risk, _CATEGORY_TO_CLASS[top_hit.category]))
    if sem_hit is not None:
        corroborated = h_risk >= ATTACK_THRESHOLD or (
            llm_verdict is not None and llm_verdict.is_attack
        )
        if sem_hit.similarity >= SEMANTIC_ALONE_SIMILARITY or corroborated:
            candidates.append((sem_hit.severity, _CATEGORY_TO_CLASS[sem_hit.category]))
    if llm_verdict is not None and llm_verdict.is_attack:
        candidates.append((llm_verdict.risk_score, llm_verdict.attack_class))

    if candidates:
        final_risk, attack_class = max(candidates, key=lambda c: c[0])
        is_attack = final_risk >= ATTACK_THRESHOLD
    else:
        final_risk = 0
        attack_class = "benign"
        is_attack = False

    preview = text if len(text) <= 160 else text[:157] + "..."
    verdict = EnsembleVerdict(
        is_attack=is_attack,
        final_risk=final_risk,
        attack_class=attack_class if is_attack else "benign",
        heuristic_hits=hits,
        heuristic_risk=h_risk,
        semantic_hit=sem_hit,
        llm_verdict=llm_verdict,
        layers_used=layers,
        latency_ms=int((time.perf_counter() - t0) * 1000),
        text_preview=preview,
    )

    if record:
        from backend import audit

        audit.record(verdict, source)
    return verdict
