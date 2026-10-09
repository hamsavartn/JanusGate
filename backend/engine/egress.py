"""Egress defense — inspect agent OUTPUT before it leaves the system.

Ingress layers catch attacks coming IN; this layer catches secrets going OUT:
  - canary tripwire: a token planted in the system prompt; if it appears in a reply,
    exfiltration of the system prompt is certain (production technique)
  - credential shapes: API keys, AWS keys, JWTs, private key blocks, Bearer tokens
  - system-prompt echo: verbatim 8-gram overlap with the configured system prompt
"""
import time

from backend.config import SENTINEL_CANARY_TOKEN, SENTINEL_SYSTEM_PROMPT
from backend.schemas import EgressVerdict

_SECRET_PATTERNS: list[tuple[str, int, str]] = [
    (r"sk-[A-Za-z0-9_-]{16,}", 9, "OpenAI-style API key shape"),
    (r"AKIA[0-9A-Z]{16}", 9, "AWS access key id shape"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", 10, "Private key block"),
    (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", 7, "JWT token shape"),
    (r"Bearer [A-Za-z0-9._-]{20,}", 7, "Bearer credential"),
    (r"(api[_-]?key|password|secret|token)\s*[=:]\s*[A-Za-z0-9._/-]{8,}", 6,
     "Key/value credential pattern"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", 9, "Slack token shape"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", 9, "GitHub token shape"),
    (r"AIza[A-Za-z0-9_-]{30,}", 9, "Google API key shape"),
]


def _system_prompt_echo(text: str) -> str | None:
    """Verbatim 8-word sequence shared with the configured system prompt."""
    if not SENTINEL_SYSTEM_PROMPT:
        return None
    sys_words = SENTINEL_SYSTEM_PROMPT.split()
    if len(sys_words) < 8:
        return None
    out_words = text.split()
    n = 8
    sys_ngrams = {" ".join(sys_words[i:i + n]) for i in range(len(sys_words) - n + 1)}
    for i in range(len(out_words) - n + 1):
        gram = " ".join(out_words[i:i + n])
        if gram in sys_ngrams:
            return gram
    return None


def inspect_output(text: str) -> EgressVerdict:
    t0 = time.perf_counter()
    reasons: list[str] = []
    evidence: list[str] = []
    risk = 0

    if SENTINEL_CANARY_TOKEN and SENTINEL_CANARY_TOKEN in text:
        reasons.append("canary_detected")
        i = text.find(SENTINEL_CANARY_TOKEN)
        evidence.append(text[max(0, i - 40):i + len(SENTINEL_CANARY_TOKEN) + 40])
        risk = max(risk, 10)

    for pattern, severity, label in _SECRET_PATTERNS:
        import re as _re
        m = _re.search(pattern, text)
        if m:
            reasons.append("credential_pattern")
            snippet = m.group(0)
            # Redact the middle of credentials in evidence — never re-leak what we catch.
            evidence.append(f"{label}: {snippet[:8]}…{snippet[-4:]}" if len(snippet) > 14 else label)
            risk = max(risk, severity)

    echo = _system_prompt_echo(text)
    if echo:
        reasons.append("system_prompt_echo")
        evidence.append(f"verbatim 8-word system-prompt echo: “{echo}”")
        risk = max(risk, 9)

    return EgressVerdict(
        is_leak=bool(reasons),
        risk=risk,
        reasons=reasons,
        evidence=evidence,
        latency_ms=int((time.perf_counter() - t0) * 1000),
        canary_active=bool(SENTINEL_CANARY_TOKEN),
    )
