# AgentSentinel — Constraints & Requirements

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
| F1 | Inspect arbitrary text an agent would read; return verdict + risk 0–10 + attack class + evidence | `/inspect` |
| F2 | Layered detection ensemble: heuristics (always) + semantic similarity (embeddings or offline TF-IDF fallback) + Gemini LLM-judge (when key present) | `backend/sentinel_core.py` |
| F3 | Graceful degradation: with zero API keys the system still runs and reports which layers are active | `/health` shows active layers |
| F4 | Attack simulator: labeled payload suite → precision/recall/F1/accuracy | `/simulate`, `simulator/suite.py` |
| F5 | Held-out evaluation set (separate from the dev corpus) — reported, never tuned against | `evals/payloads_eval.py`, `evals/run_eval.py` |
| F6 | Audit log: every inspection appended (JSONL), queryable, exportable | `backend/audit.py`, `/audit` |
| F7 | Tool-call guard: wrap agent tools; block calls whose text args are attacks | `backend/guard.py` |
| F8 | Agent email surface: mock inbox by default, Agentboxd adapter when key present | `backend/surfaces/email_inbox.py` |
| F9 | Scripted end-to-end demo scenario (story: benign mail passes, injected mail blocked) | `simulator/scenarios.py`, `/demo/scenario` |
| F10 | Dashboard: Inspector, Attack suite, Inbox, Audit log tabs | `dashboard/app.py` |
| F11 | Deployable: Dockerfile + deployment guide | `Dockerfile`, `docs/deployment.md` |
| F12 | Submission kit: README (Mermaid architecture), Devpost text, 2–4 min video script | `README.md`, `docs/devpost.md`, `docs/demo-script.md` |

## 3. Hackathon submission requirements (from the official Devpost page)

1. Project title + short description (clear problem + solution)
2. Track selection: **AI + Cybersecurity**
3. Public demo video, **2–4 minutes**, posted online (YouTube), showing the problem and how the project works
4. GitHub repository with source code and a clear README
5. Written description: problem statement & target users; technical approach & components; real-world impact
6. Screenshots, architecture diagram, or deployment link
7. Teams of 1–4 students; incomplete submissions (missing video or code) are ineligible

## 4. Judging criteria → where this project answers each

| Criterion | How AgentSentinel answers it |
|-----------|------------------------------|
| Real-World Impact & Relevance | Agents reading email/documents are a real, current attack surface (OWASP LLM Top 10); must map to released track prompt — see Blueprint §8 |
| Technical Implementation & AI Use ("not just a wrapper") | 3-layer ensemble with structured-output LLM judge, measurable precision/recall/F1, offline fallback classifier |
| Innovation & Creativity | Evidence-backed verdicts + live attack simulator + audit trail, not a chatbot |
| Execution & Completeness | Working API + dashboard + eval harness + Docker, all runnable from README |
| Presentation & Communication | README with Mermaid diagram, Devpost copy, scripted demo video |

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
