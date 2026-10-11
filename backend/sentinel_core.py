"""Sentinel Core — merges detection layers into one ensemble verdict.

Layers (run concurrently where they do I/O):
  1. heuristics   (always on, deterministic, <1 ms)
  2. semantic     (corpus similarity — Gemini embeddings online, TF-IDF offline)
  3. LLM judges   (Gemini primary; Featherless-hosted open model when configured —
                   disagreement between judges is surfaced, higher-risk verdict wins)

Merge policy: fail-closed on the strongest signal — the verdict is an attack if any
layer reports an attack at/above threshold; final risk is the max across layers;
attack class comes from the highest-risk layer.
"""
import asyncio
import time

from backend.config import ATTACK_THRESHOLD
from backend.engine import heuristics
from backend.engine.judge_featherless import judge_with_available_models
from backend.engine.semantic import semantic_scan
from backend.schemas import AttackClass, EnsembleVerdict

# Corroboration boundary for an UNCORROBORATED semantic hit, per mode — both values
# picked from the DEV corpus separation band only (tfidf: benign max 0.247, attacks 1.0;
# gemini: benign max 0.893, attacks 1.0 — embedding cosines run high, so gemini mode
# declares standalone attacks only on near-verbatim corpus matches; paraphrases are the
# LLM judge's job). Never tuned against the held-out or external sets.
SEMANTIC_ALONE_SIMILARITY = {"tfidf": 0.70, "gemini": 0.90}

# Maps heuristic/semantic categories onto the shared AttackClass vocabulary
_CATEGORY_TO_CLASS: dict[str, AttackClass] = {
    "injection": "direct_injection",
    "jailbreak": "jailbreak",
    "tool_hijack": "tool_hijack",
    "exfiltration": "exfiltration",
    "phishing": "phishing",
}


async def inspect_text(text: str, source: str = "user_message", record: bool = True,
                       session_id: str | None = None) -> EnsembleVerdict:
    t0 = time.perf_counter()

    hits = heuristics.scan(text)
    h_risk = heuristics.heuristic_risk(hits)

    # Semantic + LLM layers do network I/O — run them concurrently.
    sem_hit, (llm_verdict, judges_disagree, judge_status) = await asyncio.gather(
        asyncio.to_thread(semantic_scan, text),
        asyncio.to_thread(judge_with_available_models, text, source),
    )

    layers = ["heuristics"]
    if sem_hit is not None:
        layers.append("semantic")
    if llm_verdict is not None:
        layers.append("llm_judge")

    # --- ensemble merge: collect (risk, class) candidates from each firing layer ---
    # Corroboration principle: a semantic-only hit declares an attack when similarity is
    # high-confidence (>= SEMANTIC_ALONE_SIMILARITY) or another layer corroborates it.
    from backend.policy import session_should_block, threshold_for, update_session_risk

    # Fetch threshold early to use for BOTH corroboration and the final gate
    threshold = threshold_for(source)

    candidates: list[tuple[int, AttackClass]] = []
    if hits:
        top_hit = max(hits, key=lambda h: h.severity)
        candidates.append((h_risk, _CATEGORY_TO_CLASS[top_hit.category]))
    if sem_hit is not None:
        corroborated = h_risk >= threshold or (
            llm_verdict is not None and llm_verdict.is_attack
        )
        alone_key = "tfidf" if sem_hit.mode.startswith("tfidf") else "gemini"
        alone_needed = SEMANTIC_ALONE_SIMILARITY.get(alone_key, 0.90)
        if sem_hit.similarity >= alone_needed or corroborated:
            candidates.append((sem_hit.severity, _CATEGORY_TO_CLASS[sem_hit.category]))
    if llm_verdict is not None:
        risk = llm_verdict.risk_score
        # The boolean `is_attack` is authoritative for LLM intent.
        # If the LLM says it's an attack, but the risk_score is too low, bump it to the threshold
        # to ensure it's not silently overridden at the gate.
        if llm_verdict.is_attack and risk < threshold:
            risk = threshold
        if risk > 0:
            candidates.append((risk, llm_verdict.attack_class))

    # --- single-text risk, before policy ---
    if candidates:
        final_risk, attack_class = max(candidates, key=lambda c: c[0])
        single_attack = final_risk >= threshold
    else:
        final_risk, attack_class, single_attack = 0, "benign", False

    # --- policy: session accumulation escalates repeated sub-threshold probing ---
    session_score = update_session_risk(session_id, final_risk, single_attack)
    escalated = session_should_block(session_score)
    is_attack = single_attack or escalated
    if escalated:
        if not single_attack:
            attack_class = "direct_injection"  # repeated probing → injection buildup
            final_risk = max(final_risk, 6)
        layers.append("session_policy")

    preview = text if len(text) <= 160 else text[:157] + "..."
    verdict = EnsembleVerdict(
        is_attack=is_attack,
        final_risk=final_risk,
        attack_class=attack_class if is_attack else "benign",
        heuristic_hits=hits,
        heuristic_risk=h_risk,
        semantic_hit=sem_hit,
        llm_verdict=llm_verdict,
        judge_status=judge_status,
        judges_disagree=judges_disagree,
        layers_used=layers,
        latency_ms=int((time.perf_counter() - t0) * 1000),
        text_preview=preview,
    )

    if record:
        from backend import audit

        audit.record(verdict, source)
    return verdict
