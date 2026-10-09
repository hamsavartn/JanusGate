# JanusGate — Constraints & Requirements

Single source of truth for what must / must not be done on this project.
Any agent or human working here reads this file FIRST and follows it exactly.

---

## 1. Hard constraints (from the project owner — non-negotiable)

| # | Constraint | Enforcement |
|---|-----------|-------------|
| C1 | **No global environment changes.** No global pip installs, no system-wide config edits, no global git config changes, no installs outside the project folder — without explicit owner approval first. | All Python deps only in `agent-sentinel/.venv`. Git identity set per-repo or per-command, never `--global`. |
| C2 | **Everything lives inside `C:\Users\ASUS\Desktop\Forge_hacks`.** Nothing writes outside it. | Verify with `git status` + manual file review before commits. |
| C3 | **Secrets never touch the repo.** API keys only in `.env`, which is gitignored from the first commit. | `.gitignore` line 3; pre-commit check `git ls-files` must not list `.env`. |
| C4 | **Hackathon deadline: Oct 10, 2026, 12:00 PM EDT.** Submissions lock then. Target: submit ≥2 h early (by 10:00 AM EDT). | Roadmap in `docs/PROJECT_BLUEPRINT.md` §7. |
| C5 | **Submission requirements are eligibility** — missing video or code = not judged. Full list in §3. | Checklist in `README.md` and `docs/devpost.md`. |
| C6 | **One track only: AI + Cybersecurity.** The project must visibly answer the official track prompt once released (Discord / forgehacks.dev). | `docs/PROJECT_BLUEPRINT.md` §3 explains the choice; §8 the adaptation plan. |
| C7 | **Honest claims only.** No fabricated metrics, no invented sponsor usage, no overstated AI depth. Every number in the README/Devpost must be reproducible by running `evals/run_eval.py`. | Chain-of-verification in `evals/verify_system.py`; methodology disclosed next to every metric. |

## 2. Project requirements (functional)

| # | Requirement | Status |
|---|-------------|--------|
| F1 | Inspect arbitrary text an agent would read; verdict + risk 0–10 + attack class + evidence | `/inspect` |
| F2 | Layered ingress ensemble: 14 heuristic rules + invisible-char detector (always on) · semantic similarity (Gemini embeddings online, TF-IDF word+char channels offline, mode-aware corroboration) · LLM judges (Gemini primary + Featherless-hosted open model; disagreement surfaced, fail-closed merge) | `backend/sentinel_core.py`, `backend/engine/` |
| F3 | Graceful degradation: zero keys → runs on heuristics + TF-IDF; quota exhaustion → judge circuit-breaker + live-embed fallback to TF-IDF; active layers reported per verdict | `/health`, `layers_used` field |
| F4 | Attack simulator: 41-payload labeled dev suite → precision/recall/F1/accuracy | `/simulate`, `simulator/suite.py` |
| F5 | Held-out evaluation set (26 payloads, separate file) — reported, never tuned against; disclosed that the tuning loop once saw its misses | `evals/payloads_eval.py`, `evals/run_eval.py` |
| F6 | Tamper-evident audit: hash-chained JSONL (seq/prev_hash/hash), queryable, exportable, verifiable; optional privacy redaction mode | `backend/audit.py`, `/audit`, `/audit/verify` |
| F7 | Tool-call guard: wrap agent tools; block calls whose text args are attacks; agent replies also egress-inspected | `backend/guard.py` |
| F8 | Agent email surface: mock inbox (6 mails incl. impersonation demo) by default; Agentboxd adapter when key present; per-mail scam reports | `backend/surfaces/email_inbox.py`, `/email/inbox` |
| F9 | Scripted end-to-end demo scenario (benign passes, phishing + injected invoice + impersonation + tool-hijack blocked) | `simulator/scenarios.py`, `/demo/scenario` |
| F10 | Dashboard: 7 tabs — Inspector, Egress & canary, Attack suite, Agent inbox (scam reports), Demo scenario, Audit & analytics (charts, feedback, CSV), About | `dashboard/app.py` |
| F11 | Deployable: Dockerfile + docker-compose (API + dashboard) + deployment guide | `Dockerfile`, `docker-compose.yml`, `docs/deployment.md` |
| F12 | Submission kit: README (Mermaid architecture + honest metrics), Devpost copy with verbatim prompt mapping, 2–4 min video script, threat model, integrations cookbook | `README.md`, `docs/devpost.md`, `docs/demo-script.md`, `docs/threat-model.md`, `docs/integrations.md` |
| F13 | Egress defense: canary tripwire, credential-shape detection (redacted evidence), system-prompt echo | `backend/engine/egress.py`, `/inspect_output`, `/canary` |
| F14 | Scam & impersonation reports: brand impersonation, lookalike domains, fraud-pressure signals, archetype, safe-response advice | `backend/engine/scam.py`, `/scam_report` |
| F15 | Policy engine: per-source thresholds (email stricter) + decaying session-risk escalation | `backend/policy.py` |
| F16 | OpenAI-compatible proxy: ingress-block before upstream, egress-check the reply, `sentinel` metadata; non-streaming (documented) | `backend/proxy.py`, `/v1/chat/completions` |
| F17 | MCP server: inspect_text / inspect_output / audit_verify tools (mcp 2.x stdio) | `backend/mcp_server.py` |
| F18 | Human feedback loop: record verdict corrections + agreement stats | `/feedback`, `/feedback/stats` |
| F19 | Measurement discipline: p50/p95 latency, bootstrap recall CI, report.json, CI regression gate (F1 floor 0.9), external public validation set (546 samples, caveats disclosed) | `evals/`, `.github/workflows/ci.yml` |
| F20 | Offline-deterministic tests; live-key measurement only in eval runners | `tests/conftest.py`, 35 tests |

## 3. Hackathon submission requirements (from the official Devpost page)

1. Project title + short description (clear problem + solution)
2. Track selection: **AI + Cybersecurity**
3. Public demo video, **2–4 minutes**, posted online (YouTube), showing the problem and how the project works
4. GitHub repository with source code and a clear README
5. Written description: problem statement & target users; technical approach & components; real-world impact
6. Screenshots, architecture diagram, or deployment link
7. Teams of 1–4 students; incomplete submissions (missing video or code) are ineligible

## 4. Judging criteria → where this project answers each

| Criterion | How JanusGate answers it |
|-----------|------------------------------|
| Real-World Impact & Relevance | People-first: scams/impersonation/fraud answered via scam reports + agent firewall; verbatim prompt mapping in `docs/devpost.md` (recognize/prevent/verify/respond) |
| Technical Implementation & AI Use ("not just a wrapper") | 3-layer ingress ensemble + multi-judge merge + egress defense + policy engine; measurable precision/recall/F1 with disclosed methodology |
| Innovation & Creativity | Canary tripwire, tamper-evident audit chain, scam-signal reports, OpenAI-compatible drop-in proxy, MCP server |
| Execution & Completeness | 13 API routes + dashboard + evals + CI + Docker, all runnable from README; 35 tests + 16-point verification |
| Presentation & Communication | README with Mermaid + screenshots, Devpost copy, threat model, scripted video |

## 5. Non-functional requirements

- Windows-first dev environment (Git Bash paths); code must stay OS-neutral (pathlib, no POSIX-only calls).
- Python 3.13 venv; Node not required for the current dashboard (Streamlit).
- API failures must never crash inspection — every external call wrapped, layer degrades silently.
- Latency budget: heuristic layer <5 ms typical; LLM layer best-effort (seconds), never blocking heuristics.

## 6. Out of scope (accepted cuts)

- No user auth / multi-tenancy.
- No model fine-tuning (ensemble + structured prompting only).
- No real-time streaming UI (refresh-based dashboard is fine).
- Actual cloud deployment and video recording are the owner's steps (accounts/voice needed) — everything else is prepared.
