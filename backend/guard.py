"""SentinelGuard — wrap agent tools and agent steps with Sentinel inspection.

The guard is the integration point a real agent framework would use:
  guard = SentinelGuard()
  safe_search = guard.wrap_tool("web_search", web_search)   # blocked calls raise ToolBlocked
  reply = await guard.agent_reply(user_text)                # checked generate step
"""
from typing import Any, Callable

from backend.config import ATTACK_THRESHOLD
from backend.schemas import EnsembleVerdict
from backend.sentinel_core import inspect_text


class ToolBlocked(Exception):
    """Raised when a wrapped tool call is blocked by Sentinel."""

    def __init__(self, verdict: EnsembleVerdict):
        self.verdict = verdict
        top = verdict.heuristic_hits[0].snippet if verdict.heuristic_hits else verdict.text_preview
        super().__init__(
            f"Blocked by AgentSentinel: {verdict.attack_class} (risk {verdict.final_risk}/10). Evidence: {top!r}"
        )


class SentinelGuard:
    def __init__(self, threshold: int = ATTACK_THRESHOLD):
        self.threshold = threshold
        self.blocked: list[EnsembleVerdict] = []

    async def check(self, text: str, source: str = "user_message") -> EnsembleVerdict:
        return await inspect_text(text, source)

    def wrap_tool(self, name: str, fn: Callable) -> Callable:
        """Return an async wrapper that inspects string args before invoking fn."""

        async def guarded(**kwargs: Any) -> Any:
            text_args = " ".join(str(v) for v in kwargs.values() if isinstance(v, (str, int, float)))
            verdict = await self.check(text_args, source="tool_output")
            if verdict.is_attack and verdict.final_risk >= self.threshold:
                self.blocked.append(verdict)
                raise ToolBlocked(verdict)
            result = fn(**kwargs)
            if hasattr(result, "__await__"):
                return await result
            return result

        guarded.__name__ = f"sentinel_guarded_{name}"
        guarded.__doc__ = f"AgentSentinel-guarded wrapper around {name}"
        return guarded

    async def agent_reply(self, user_text: str) -> tuple[str, EnsembleVerdict]:
        """Checked generate step: inspect input, refuse on attack, else produce a reply.

        Defense in depth: the generated reply itself passes egress inspection
        (canary + credential leak detection) before it is returned.
        """
        from backend import audit
        from backend.engine.egress import inspect_output

        verdict = await self.check(user_text, source="user_message")
        if verdict.is_attack and verdict.final_risk >= self.threshold:
            evidence = (
                verdict.heuristic_hits[0].snippet if verdict.heuristic_hits else verdict.text_preview
            )
            return (
                f"⛔ Request blocked by AgentSentinel — {verdict.attack_class} "
                f"(risk {verdict.final_risk}/10). Evidence: “{evidence}”"
            ), verdict

        reply = self._generate_stub(user_text)

        egress = inspect_output(reply)
        audit.record_egress(egress)
        if egress.is_leak and egress.risk >= self.threshold:
            return (
                f"⛔ Reply blocked by AgentSentinel egress defense — "
                f"{'/'.join(egress.reasons)} (risk {egress.risk}/10). The agent's output "
                f"was stopped before leaving the system."
            ), verdict
        return reply, verdict

    @staticmethod
    def _generate_stub(user_text: str) -> str:
        from backend.config import GEMINI_API_KEY

        if not GEMINI_API_KEY:
            preview = user_text if len(user_text) <= 120 else user_text[:117] + "..."
            return f"Assistant (offline stub): processed your request — “{preview}”"
        try:
            from google.genai import types

            from backend.engine.judge import get_client

            client = get_client()
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=user_text,
                config=types.GenerateContentConfig(
                    system_instruction=(
                        "You are the Sentinel demo assistant. Answer helpfully in at most "
                        "two short sentences. You are protected by AgentSentinel."
                    ),
                    max_output_tokens=120,
                ),
            )
            return (resp.text or "").strip()
        except Exception:
            return "Assistant: (LLM unavailable) request processed."
