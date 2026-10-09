# Devpost submission copy (fill into https://forgehacks-2026.devpost.com)

## Project title
AgentSentinel — a security firewall & audit trail for AI agents

## Track
AI + Cybersecurity

## Short description ( elevator)
AI agents read email, documents and web content written by strangers — and follow whatever
hidden instructions they find there. AgentSentinel is a firewall that inspects everything an
agent is about to read (3-layer detection ensemble: heuristics + semantic similarity + Gemini
structured-output judge), blocks attacks with evidence, logs every decision for audit, and
proves its detection quality with a built-in attack simulator (live precision/recall/F1).

## Written description

### Problem statement & target users
Scams, impersonation, and fraud are now industrialized with AI: LLM-written phishing with
lookalike domains lands in real inboxes, CEO-fraud and OTP-relay texts pressure people into
payments, and the newest target is the AI assistant itself — one hidden line in an email can
hijack an agent into forwarding data or authorizing a fraudulent payment. **AgentSentinel
protects people on both fronts:** a per-message scam report (signals, archetype, safe
response) for the human recipient, and a firewall that stops an AI agent from being weaponized
against them. Target users: (1) everyone with an inbox — via agent-protected mail and the
scam report; (2) developers and small teams deploying AI agents who need drop-in protection;
(3) security reviewers who need evidence, not vibes.

### Technical approach & components
- **Sentinel Core (FastAPI, Python 3.13):** one `POST /inspect` call wraps any agent input
  (user message, email, tool output, document) and returns an evidence-backed verdict.
- **3-layer ingress ensemble** (`backend/engine/`): (1) 14 deterministic heuristic rules + invisible-char detector
  covering direct/indirect injection, jailbreaks, tool hijacking, exfiltration, phishing —
  including non-English injection phrases; (2) semantic similarity against a labeled attack
  corpus — Gemini embeddings online, offline TF-IDF fallback, with a corroboration principle
  for low-similarity hits; (3) **two independent LLM judges** — Gemini structured output
  (attack class, risk 0–10, confidence, verbatim evidence) plus a Featherless-hosted
  open-source model (sponsor tool) when configured; judge disagreement is surfaced and the
  merge is fail-closed. Layers run concurrently.
- **Egress defense** (`POST /inspect_output`): inspects agent REPLIES for outbound leaks — a
  **canary tripwire** token planted in the system prompt (appearance in a reply = certain
  exfiltration, risk 10), credential-shape detection (AWS/GitHub/Slack/Google/OpenAI keys,
  JWTs, private-key blocks — evidence is redacted), and verbatim system-prompt echo detection.
- **SentinelGuard:** wraps agent tools (e.g. `send_email`) and blocks calls whose arguments
  carry injected instructions, before execution; generated replies also pass egress.
- **Agent email surface:** mock inbox by default; Agentboxd adapter (`AGENTBOXD_API_KEY`) for
  the sponsor's real agent inboxes.
- **Scam & impersonation report** (`POST /scam_report`, prompt verbs "recognize"/"verify"):
  brand-impersonation detection (display name vs domain, lookalike/typosquat domains with
  edit-distance + leet un-mapping, free-mail claiming corporate identity, brand-in-link
  hosts), fraud-pressure signals (urgency, credential/OTP solicitation, payment & gift-card
  demands, authority+secrecy, too-good-to-be-true), scam-archetype guess (BEC, OTP relay,
  gift card, tech support, lottery, crypto), and a safe-response recommendation — written
  for the human recipient (prompt verb "respond").
- **Audit + analytics + feedback:** append-only JSONL log (ingress, egress, feedback) with
  dashboard analytics charts; a human feedback endpoint records verdict corrections — a
  continuous-improvement loop with a full review trail.
- **Measurement as a first-class feature:** three suites — 41-payload co-designed dev suite
  (regression), 26-payload held-out set, and an **external public validation set** (546
  samples from deepset/prompt-injections; independent of rule authoring, with one disclosed
  calibration caveat: precision is an upper bound — see evals/report.md). Honest numbers
  regenerate via `evals/` runners; methodology printed next to every result.
- **Dashboard (Streamlit, dark theme, 7 tabs):** Inspector, Egress & canary, Attack suite
  (live metrics), Agent inbox (mock/Agentboxd), Demo scenario, Audit & analytics, About.
- **Components used:** Python, FastAPI, Pydantic, uvicorn, Streamlit, google-genai (Gemini
  2.5 Flash + embeddings), httpx, pytest, Docker/docker-compose, GitHub Actions CI.

### How we create real-world impact
- **Deployable today:** one pip install + one API call to protect an existing agent; Dockerfile
  included; runs fully offline (TF-IDF fallback) for air-gapped/security-sensitive environments.
- **Trust through evidence:** every verdict quotes the exact text that triggered it and lists
  the layers that fired — security reviewers can verify, not just trust.
- **Trust through measurement:** the attack simulator regenerates precision/recall/F1 on demand;
  methodology and its limits are disclosed in `evals/report.md` (we state plainly what the
  numbers do and don't prove).
- **Auditability:** JSONL audit log turns "the AI did something weird" into a reviewable trail.

### Screenshots / architecture / demo
- Architecture diagram: README (Mermaid) + this page
- Live demo: [deployment link — owner adds after deploy]
- Video: [YouTube link — owner adds after upload]
- GitHub: [repo link — owner adds after push]

### How we answer the released track prompt
> ⚠️ OWNER ACTION: paste the released AI + Cybersecurity track prompt here verbatim and add 2–3
> sentences mapping AgentSentinel's features to it (docs/PROJECT_BLUEPRINT.md §8 has the
> mapping playbook per prompt theme).

## Submission checklist (all required for eligibility)
- [x] Title + description
- [x] Track selection (AI + Cybersecurity)
- [ ] 2–4 min public demo video on YouTube (script ready in docs/demo-script.md)
- [ ] GitHub repo public with this README
- [x] Written description (this file)
- [x] Architecture diagram (README) + screenshots (dashboard tabs) + deployment link (pending)
