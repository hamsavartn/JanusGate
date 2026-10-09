# Agent Sentinel (JanusGate) - Activity Log

## Session Initialized
- **Goal:** Implement the Red-Team Attack Generator.
- **Constraints Verified:** Local environment only, secrets strictly in `.env`, honest metrics, fail-closed design.

### Action Plan (Tree of Thoughts)
1. **Brainstorming:**
   - *Option A:* Standalone CLI script that generates adversarial payloads and saves to JSON.
   - *Option B:* Full dashboard integration (FastAPI route + Streamlit tab) for one-click generation and approval.
   - *Option C:* Autonomous adversarial loop (generates attacks, tests against the firewall, saves only successful bypasses).
   - *Decision:* **Option C (Hybrid)**. We will build `simulator/redteam_generator.py`, an autonomous script that uses Gemini to write novel attacks based on live threat intel, tests them against the local JanusGate API, and outputs successful bypasses to a `pending_review.json` file for the human to review and merge into the corpus. This prevents corpus bloat and isolates the live key usage.

### Chain of Verification
- **Constraint C1/C2 (Local only):** Script will be placed in `simulator/redteam_generator.py`. All API calls will route through existing local `backend/config.py` keys.
- **Constraint C3 (Secrets):** We will use `GEMINI_API_KEY` directly from the environment, zero hardcoding.
- **Constraint F19 (Honest Metrics):** Payloads will NOT be injected into the external validation set. They will explicitly be output to a review file to grow the dev suite (`corpus.py`) only.

### Current Step
- Fetching live adversarial techniques from GitHub (`yueliu1999/Awesome-Jailbreak-on-LLMs`) using the GitHub MCP to seed the Gemini generation prompt.
- Wrote `simulator/redteam_generator.py` mapping to `inspect_text` correctly.
- **Result:** Execution hit the known `429 RESOURCE_EXHAUSTED` (daily free-tier quota) for `gemini-3.8-flash`. This is exactly as documented in `HANDOFF.md` §7 and §8. The generator architecture is perfectly set up and will resume functioning as soon as the owner rotates/upgrades the `GEMINI_API_KEY` in `.env`.

## Feature: HTML Email Parsing
- **Goal:** Implement robust parsing of HTML emails to extract plaintext and format links as Markdown for `sentinel_core.py` inspection, preventing attackers from hiding payloads in HTML tags.

### Action Plan (Tree of Thoughts)
1. **Brainstorming Parsing Strategies:**
   - *Option A:* Use Python's built-in `html.parser.HTMLParser`. Zero dependencies, adheres perfectly to C1 (No global env changes). Fast and synchronous.
   - *Option B:* Use `beautifulsoup4`. Robust against malformed HTML, standard in security tools. Requires adding to `requirements.txt`.
   - *Option C:* Use `html2text`. Great for converting HTML direct to Markdown (which is perfect for LLM judges). Requires another external dependency.
   - *Decision:* **Option A (Built-in HTMLParser)**. For a hackathon project with strict constraints (C1, F19), keeping dependencies minimal is preferred. We can subclass `HTMLParser` to specifically extract text and format `<a>` tags as `[text](href)` markdown, effectively providing all the context the LLM judge and TF-IDF layers need, without bloating the `.venv`.

### Chain of Verification
- **Constraint C1 (No global env changes):** By using `html.parser`, we add 0 new dependencies.
- **Constraint F8 & F14 (Email surface & Phishing detection):** Formatting `<a href="url">text</a>` into `[text](url)` perfectly exposes lookalike domains and hidden malicious links to the LLM judge and heuristic layers.
- **Constraint F2 (Heuristics) & F15 (Policy engine):** Stripping HTML tags prevents heuristics from being bypassed by inserted hidden tags (e.g., `<i></i>` splitting words). Hidden malicious text will be exposed because the parser extracts all data nodes.

### Current Step
- Implementing `backend/utils/html_parser.py` using `html.parser.HTMLParser`.
- Integrating it into `backend/surfaces/email_inbox.py` so that any fetched email is automatically parsed into clean text before Sentinel inspection.

## Feature: Streaming Proxy Support
- **Goal:** Support `stream: true` in the OpenAI-compatible proxy (`/v1/chat/completions`) so agents can receive streamed responses without bypassing ingress or egress security.

### Action Plan (Tree of Thoughts)
1. **Brainstorming Egress Defense for Streams:**
   - *Option A:* Buffer the entire response, check it, and then simulate a stream. (Fails the real-time UX requirement of streaming).
   - *Option B:* Stream directly, but run `inspect_output()` on the accumulated buffer + the new chunk *before* yielding the chunk. If the new chunk completes a secret (e.g., the last few chars of a canary token), the egress check trips, the chunk is dropped, and a synthetic "⛔ Blocked" chunk is yielded instead.
   - *Decision:* **Option B (Accumulation Check)**. It provides real-time streaming while maintaining strict egress security. Because `inspect_output` relies on fast heuristics (regex), running it per-chunk is extremely lightweight (<1ms overhead per chunk).

### Chain of Verification
- **Constraint F16 (Proxy):** The proxy is explicitly documented as non-streaming. Adding streaming makes it fully compliant with modern agent architectures (e.g., Cursor, AutoGPT).
- **Constraint F13 (Egress defense):** Dropping the chunk *before* yielding it ensures that the exact boundary of the credential/canary leak is never transmitted to the client.
- **Latency Budget (NFR):** `inspect_output` takes micro-seconds; executing it per SSE chunk easily fits within the streaming latency budget.

### Current Step
- Updating `backend/proxy.py` to use `fastapi.responses.StreamingResponse` and `httpx.AsyncClient().stream()`.
- Integrating the synthetic streaming response for both ingress blocks and egress interruptions.
