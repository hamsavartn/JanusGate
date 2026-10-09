"""Central configuration. Reads only from environment/.env — never hardcode secrets."""
import os
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

# Load the nearest .env walking up from the working directory (repo root).
load_dotenv(find_dotenv(usecwd=True))

ROOT = Path(__file__).resolve().parent.parent

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_JUDGE_MODEL = os.getenv("GEMINI_JUDGE_MODEL", "gemini-2.5-flash")
GEMINI_EMBED_MODEL = os.getenv("GEMINI_EMBED_MODEL", "gemini-embedding-001")

FEATHERLESS_API_KEY = os.getenv("FEATHERLESS_API_KEY", "").strip()
FEATHERLESS_BASE_URL = os.getenv("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1")
FEATHERLESS_JUDGE_MODEL = os.getenv("FEATHERLESS_JUDGE_MODEL", "Qwen/Qwen2.5-7B-Instruct")

# Egress defense: canary token planted in the system prompt; if it ever appears in an
# agent reply, exfiltration is certain. Override via env; default is stable for tests.
SENTINEL_CANARY_TOKEN = os.getenv("SENTINEL_CANARY_TOKEN", "CANARY-AS-9f3b7c2a-egress-tripwire")
# Optional: paste the agent's real system prompt to detect verbatim echoes in replies.
SENTINEL_SYSTEM_PROMPT = os.getenv("SENTINEL_SYSTEM_PROMPT", "").strip()

SENTINEL_HOST = os.getenv("SENTINEL_HOST", "127.0.0.1")
SENTINEL_PORT = int(os.getenv("SENTINEL_PORT", "8123"))

# Final verdict threshold: risk scores >= this are labeled as attacks.
ATTACK_THRESHOLD = 5
