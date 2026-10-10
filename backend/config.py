"""Central configuration. Reads only from environment/.env — never hardcode secrets."""
import os
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

# Load the nearest .env walking up from the working directory (repo root).
load_dotenv(find_dotenv(usecwd=True))

ROOT = Path(__file__).resolve().parent.parent

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_JUDGE_MODEL = os.getenv("GEMINI_JUDGE_MODEL", "gemini-3.8-flash")
GEMINI_EMBED_MODEL = os.getenv("GEMINI_EMBED_MODEL", "gemini-embedding-001")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_JUDGE_MODEL = os.getenv("GROQ_JUDGE_MODEL", "qwen-2.5-32b") # Note: qwen-2.5-32b is the api ID for qwen3.8-27b on Groq, let me double check the exact model string, user's screenshot had qwen/qwen3.8-27b. I will use qwen/qwen3.8-27b.
GROQ_JUDGE_MODEL = os.getenv("GROQ_JUDGE_MODEL", "qwen/qwen3.8-27b")

# Egress defense: canary token planted in the system prompt; if it ever appears in an
# agent reply, exfiltration is certain. Override via env; default is stable for tests.
SENTINEL_CANARY_TOKEN = os.getenv("SENTINEL_CANARY_TOKEN", "CANARY-AS-9f3b7c2a-egress-tripwire")
# Optional: paste the agent's real system prompt to detect verbatim echoes in replies.
SENTINEL_SYSTEM_PROMPT = os.getenv("SENTINEL_SYSTEM_PROMPT", "").strip()

# Audit privacy: when "1", stored previews are redacted (first 24 chars + hash) so the
# log proves what was inspected without storing user content in the clear.
AUDIT_REDACT = os.getenv("AUDIT_REDACT", "0") == "1"

# Per-source policy thresholds: emails are held to a stricter standard than direct
# user messages (attacker controls email content; users see their own prompts).
SOURCE_THRESHOLDS: dict[str, int] = {
    "user_message": int(os.getenv("THRESHOLD_USER_MESSAGE", "5")),
    "tool_output": int(os.getenv("THRESHOLD_TOOL_OUTPUT", "5")),
    "email": int(os.getenv("THRESHOLD_EMAIL", "4")),
    "document": int(os.getenv("THRESHOLD_DOCUMENT", "4")),
}
# Session risk: repeated sub-threshold probing escalates. Score decays ~half each
# 10 minutes; sessions at/above this are escalated regardless of single-text verdict.
SESSION_RISK_BLOCK = int(os.getenv("SESSION_RISK_BLOCK", "12"))
SESSION_HALF_LIFE_MIN = float(os.getenv("SESSION_HALF_LIFE_MIN", "10"))

# Upstream for proxy mode (OpenAI-compatible). Gemini exposes an OpenAI-compatible
# endpoint, so the same key works; any OpenAI-compatible provider can be substituted.
UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
UPSTREAM_API_KEY = os.getenv("UPSTREAM_API_KEY", GEMINI_API_KEY)
UPSTREAM_DEFAULT_MODEL = os.getenv("UPSTREAM_DEFAULT_MODEL", "gemini-2.5-flash")

SENTINEL_HOST = os.getenv("SENTINEL_HOST", "127.0.0.1")
SENTINEL_PORT = int(os.getenv("SENTINEL_PORT", "8123"))

# Final verdict threshold: risk scores >= this are labeled as attacks.
ATTACK_THRESHOLD = 5
