"""Policy engine — per-source thresholds + multi-turn session risk accumulation.

Why: a firewall with one global threshold is either too jumpy or too deaf.
  - Emails/documents are held to a stricter threshold than user messages (the user sees
    their own prompts; nobody vetted the email).
  - Attackers often build up over multiple turns, each text individually sub-threshold.
    The session accumulator decays (half-life) and escalates when the pattern persists.

Session state is in-memory (single-process deployments); for multi-worker deployments a
Redis backend would slot into the same interface (documented in docs/PROJECT_BLUEPRINT.md).
"""
import threading
import time

from backend.config import SESSION_HALF_LIFE_MIN, SESSION_RISK_BLOCK, SOURCE_THRESHOLDS

_lock = threading.Lock()
_sessions: dict[str, tuple[float, float]] = {}  # session_id -> (last_ts, risk_score)


def threshold_for(source: str) -> int:
    return SOURCE_THRESHOLDS.get(source, 5)


def _decay(score: float, elapsed_min: float) -> float:
    return score * (0.5 ** (elapsed_min / max(SESSION_HALF_LIFE_MIN, 0.1)))


def update_session_risk(session_id: str | None, risk: int, is_attack: bool) -> float:
    """Add this verdict's risk to the session accumulator; return the new session score."""
    global _sessions
    if not session_id:
        return 0.0
    now = time.time()
    with _lock:
        last_ts, score = _sessions.get(session_id, (now, 0.0))
        score = _decay(score, (now - last_ts) / 60.0)
        # Sub-threshold probing still accumulates, just slower than real attacks.
        score += float(risk) if is_attack else max(0.0, risk * 0.5)
        _sessions[session_id] = (now, score)
        if len(_sessions) > 10000:  # bound memory
            cutoff = now - SESSION_HALF_LIFE_MIN * 6 * 60
            _sessions = {k: v for k, v in _sessions.items() if v[0] > cutoff}
        return round(score, 2)


def session_should_block(session_score: float) -> bool:
    return session_score >= SESSION_RISK_BLOCK
