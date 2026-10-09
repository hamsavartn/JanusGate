"""AgentSentinel API — inspect text, run the attack suite, health.

Run from the repo root (agent-sentinel/):
    .venv/Scripts/python.exe -m uvicorn backend.main:app --port 8123
"""
from fastapi import FastAPI

from backend.config import GEMINI_API_KEY, SENTINEL_HOST, SENTINEL_PORT
from backend.schemas import EnsembleVerdict, InspectRequest, ScenarioResult, SuiteResult
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=SENTINEL_HOST, port=SENTINEL_PORT)
