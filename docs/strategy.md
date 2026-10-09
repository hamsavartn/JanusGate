# ForgeHacks 2026 — JanusGate Strategy

## The hackathon
- **ForgeHacks Online 2026** — student-only, fully online, Oct 3–12 2026. Theme: AI for Real
  World Problems, six fixed tracks. Track prompts dropped Oct 3 (Day 1).
- **Deadline: Oct 10, 12:00 PM EDT** (submissions lock). Judging Oct 10–11; winners Oct 12.
- **Must submit:** title + description · one track · public 2–4 min YouTube demo video ·
  GitHub repo + README · written description (problem, users, tech, impact) · screenshots /
  architecture / deploy link. **Missing video or code = ineligible.**
- **Judging (5 criteria):** Real-World Impact & Relevance (must answer the track prompt) ·
  Technical Implementation & AI Use (explicitly *not just a wrapper*) · Innovation & Creativity ·
  Execution & Completeness · Presentation & Communication.
- **Tracks:** AI + Healthcare / Education / Climate / Business / Cybersecurity / Creativity.
  Cybersecurity track prize is by far the largest: $100 cash + 6-month Agentboxd Team plan.

## Why track = AI + Cybersecurity
1. Biggest track prize (~$470 vs ~$10 for other tracks).
2. Least crowded track at student hackathons → better odds for the track prize and more
   visibility for overall judging.
3. Sponsor synergy: **Agentboxd** (gives AI agents real email inboxes, checks inbound mail for
   prompt injection & phishing) → we build the defense/verification layer on top.
4. Security work can *prove* AI substance with measurable metrics (precision/recall on an
   attack suite) — directly answering the "not just a wrapper" criterion.

## Project: JanusGate
Security firewall + audit trail for AI agents. Four components:
1. **Sentinel Core** (FastAPI middleware) — wraps an agent's prompts/tool calls/responses.
2. **Detection ensemble** — (a) heuristics/rules, (b) embedding-similarity classifier vs a
   curated attack corpus (Day 2), (c) Gemini LLM-judge with structured JSON verdicts
   (risk score, attack class, evidence, confidence). Featherless sponsor credit = fallback
   ensemble member → visible sponsor integration.
3. **Attack simulator** — one-click payload suite (direct/indirect injection, tool-call
   hijacking, exfiltration, phishing) with live precision/recall/F1.
4. **Dashboard** (Streamlit) — scan box, verdict breakdown with evidence, run-the-suite
   scoreboard, audit log.

## 7-day roadmap
- **Day 1 (Oct 3):** prompt drop → lock scope; scaffold; venv; heuristics engine; Gemini
  judge; simulator; dashboard stub. ✅
- **Day 2:** embedding-semantic classifier (Gemini embeddings vs corpus), merge into ensemble.
- **Day 3:** tool-call instrumentation; email surface (Agentboxd or IMAP mock); audit log.
- **Day 4:** expand payload suite + eval harness; tune thresholds; metrics table in README.
- **Day 5:** dashboard polish; scripted end-to-end demo; deploy (Railway/HF Spaces).
- **Day 6:** video (2–4 min), README + Mermaid diagram, Devpost written description.
- **Day 7 (Oct 10):** buffer; submit ≥2h before 12:00 PM EDT.

## 10 must-have skills
1. LLM API engineering (Gemini structured output; OpenAI-compatible clients for Featherless)
2. Agent/tool-call architecture (function-calling loops, middleware instrumentation)
3. Python backend (FastAPI, async)
4. Dashboard frontend (Streamlit/React) with live updates
5. Embeddings/RAG + classifier ensembles
6. Evaluation discipline (test sets, precision/recall)
7. Security domain knowledge (OWASP LLM Top 10, injection taxonomy, phishing signals)
8. Deployment (Docker, Railway/Render/HF Spaces)
9. Git/GitHub hygiene + README + architecture diagrams
10. Demo storytelling & video production

## Hard rules (user constraint)
Everything stays inside `C:\Users\ASUS\Desktop\Forge_hacks`. Local `.venv` only — no global
installs, no global config changes without explicit approval. Secrets live in `.env`
(gitignored) and are never committed.
