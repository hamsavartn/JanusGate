"""AgentSentinel API — inspect text, run the attack suite, health.

Run from the repo root (agent-sentinel/):
    .venv/Scripts/python.exe -m uvicorn backend.main:app --port 8123
"""
from fastapi import FastAPI

from backend.config import GEMINI_API_KEY, SENTINEL_HOST, SENTINEL_PORT
from backend.schemas import (
    EgressVerdict,
    EnsembleVerdict,
    FeedbackEntry,
    InspectRequest,
    OutputRequest,
    ScenarioResult,
    SuiteResult,
)
from backend.sentinel_core import inspect_text

app = FastAPI(
    title="AgentSentinel",
    version="0.1.0",
    description="Security firewall + audit trail for AI agents (ForgeHacks 2026).",
)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "agentsentinel",
        "version": "0.1.0",
        "llm_judge_active": bool(GEMINI_API_KEY),
        "layers": ["heuristics"] + (["llm_judge"] if GEMINI_API_KEY else []),
    }


@app.post("/inspect", response_model=EnsembleVerdict)
async def inspect(req: InspectRequest) -> EnsembleVerdict:
    """Inspect any text an agent is about to read and return an evidence-backed verdict."""
    return await inspect_text(req.text, req.source)


@app.post("/simulate", response_model=SuiteResult)
async def simulate() -> SuiteResult:
    """Fire the labeled attack suite through the detection engine and report metrics."""
    from simulator.suite import run_suite_async

    return await run_suite_async()


@app.get("/audit")
def audit_log(limit: int = 50, only_attacks: bool = False) -> dict:
    """Query the JSONL audit log (newest first)."""
    from backend import audit

    return {"count": len(audit.query(limit=limit, only_attacks=only_attacks)),
            "entries": audit.query(limit=limit, only_attacks=only_attacks)}


@app.get("/email/inbox")
async def email_inbox() -> dict:
    """Fetch inbox (mock by default, Agentboxd when configured) + Sentinel verdict per mail."""
    from backend.surfaces.email_inbox import get_inbox

    inbox = get_inbox()
    messages = []
    for m in inbox.fetch():
        verdict = await inspect_text(
            f"Subject: {m.subject}\nFrom: {m.sender}\n\n{m.body}",
            source="email",
        )
        messages.append({
            "id": m.id,
            "sender": m.sender,
            "subject": m.subject,
            "preview": (m.body[:140] + "…") if len(m.body) > 140 else m.body,
            "is_attack": verdict.is_attack,
            "attack_class": verdict.attack_class,
            "risk": verdict.final_risk,
            "evidence": (verdict.heuristic_hits[0].snippet if verdict.heuristic_hits
                         else (verdict.semantic_hit.matched_payload if verdict.semantic_hit else None)),
        })
    return {"provider": inbox.name, "messages": messages}


@app.post("/demo/scenario", response_model=ScenarioResult)
async def demo_scenario() -> ScenarioResult:
    """Scripted end-to-end story: inbox processed, attacks blocked, tool guard trips."""
    from simulator.scenarios import run_scenario_async

    return await run_scenario_async()


@app.post("/inspect_output", response_model=EgressVerdict)
async def inspect_output_endpoint(req: OutputRequest) -> EgressVerdict:
    """Egress defense: inspect an agent REPLY for leaks (canary, credentials, echoes)."""
    import time

    from backend import audit
    from backend.engine.egress import inspect_output

    t0 = time.perf_counter()
    verdict = inspect_output(req.text)
    verdict = verdict.model_copy(update={"latency_ms": int((time.perf_counter() - t0) * 1000)})
    audit.record_egress(verdict)
    return verdict


@app.get("/canary")
def canary_status() -> dict:
    """Reveal the active canary token (so demos/tests can plant it in a fake reply)."""
    from backend.config import SENTINEL_CANARY_TOKEN

    return {"canary_active": bool(SENTINEL_CANARY_TOKEN), "token": SENTINEL_CANARY_TOKEN,
            "note": "Plant this token in your system prompt. If it ever appears in a reply, "
                    "exfiltration of the system prompt is certain."}


@app.post("/feedback")
def feedback(entry: FeedbackEntry) -> dict:
    """Human feedback on a verdict — recorded for the continuous-improvement loop."""
    from backend import audit

    audit.record_feedback(entry.model_dump())
    return {"status": "recorded", "stats": feedback_stats()}


@app.get("/feedback/stats")
def feedback_stats() -> dict:
    from backend import audit

    entries = [e for e in audit.query(limit=10000) if e.get("type") == "feedback"]
    total = len(entries)
    wrong = sum(1 for e in entries if not e.get("correct"))
    return {"total": total, "marked_wrong": wrong,
            "agreement_rate": round((total - wrong) / total, 3) if total else None}


@app.get("/audit/verify")
def audit_verify() -> dict:
    """Verify the tamper-evident hash chain of the audit log."""
    from backend import audit

    return audit.verify_chain()


@app.post("/v1/chat/completions")
async def v1_chat_completions(payload: dict):
    """OpenAI-compatible security proxy — inspect ingress, forward, inspect egress.

    Point any OpenAI-SDK agent at this base_url; attacks are blocked before the
    upstream call, leaks are blocked before the reply leaves. Responses carry a
    `sentinel` metadata object. Non-streaming only.
    """
    from backend.proxy import handle_chat_completions

    return await handle_chat_completions(payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=SENTINEL_HOST, port=SENTINEL_PORT)
