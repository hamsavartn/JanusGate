# Deep-Research Agent Brief

Copy everything below this line into your deep research agent as-is.

---

CONTEXT (self-contained — you have no prior knowledge of this):
ForgeHacks Online 2026 is a fully-online student hackathon (1–4 member teams, students only,
first edition) running Oct 3–12, 2026, on Devpost: https://forgehacks-2026.devpost.com,
main site https://www.forgehacks.dev. Theme: "AI for Real World Problems" across six fixed
tracks (AI + Healthcare, AI + Education, AI + Climate, AI + Business, AI + Cybersecurity,
AI + Creativity). Specific track prompts were released Oct 3 (Day 1) on the site/Discord.
Submissions lock Oct 10, 2026 at 12:00 PM EDT; judging Oct 10–11; winners Oct 12.
Submission requirements: project title + description, ONE track selection, public 2–4 minute
demo video on YouTube, GitHub repo with source + clear README, written description covering
problem statement, target users, technical approach, real-world impact, plus screenshots/
architecture diagram/deployment link. Missing video or code = ineligible.
Judging criteria (5): (1) Real-World Impact & Relevance — must answer the track prompt,
genuine problem, potential for actual use; (2) Technical Implementation & AI Use — quality/
depth/correctness of AI components, explicitly "not just a wrapper"; (3) Innovation &
Creativity; (4) Execution & Completeness — working demo, polish, what shipped during the event;
(5) Presentation & Communication — video, README, written description clarity.
Prizes: 1st ≈ $6,935 value ($100 cash + sponsor credits: Featherless $300, Momen $2,000,
Adaption $1,000, memberships); 2nd ≈ $2,090; 3rd ≈ $1,330; every track has a track prize
EXCEPT Cybersecurity is much larger: $100 cash + 6-month Agentboxd Team plan (~$470 total);
other tracks ≈ $10 ProjectAAL credits + certificate. All participants get sponsor credits:
Featherless ($25, 40,000+ open models, OpenAI-compatible API), Momen, n8n Cloud Pro (first 300),
Agentboxd 30-day Builder (first 800), Kariaa, YouCam API, ProjectAAL, Adaption, DevSwarm,
Tin.computer. Sponsor tools known: Agentboxd = real email inboxes + email API for AI agents,
checks incoming mail for prompt injection and phishing; Featherless = serverless inference for
open-source models; n8n = workflow automation; Momen = no-code full-stack AI app builder.
OUR PROFILE: one experienced developer (has shipped AI apps end-to-end; primary LLM = Gemini
API key with free tier; secondary = $25 Featherless sponsor credit), building ambitiously with
a multi-component architecture, targeting best overall odds.
MY CHOSEN DIRECTION: track = AI + Cybersecurity. Project = "AgentSentinel": a security
firewall + audit layer for AI agents. Components: (1) FastAPI middleware wrapping any LLM
agent's tool calls and I/O; (2) detection ensemble = heuristics + embedding-similarity
classifier (grounded on public prompt-injection datasets, OWASP LLM Top 10) + Gemini LLM-judge
producing structured verdicts with evidence; (3) one-click attack simulator firing a payload
suite (direct/indirect injection, tool hijacking, data exfiltration, phishing) with live
precision/recall metrics; (4) real-time dashboard visualizing verdicts + audit log. Email
defense module on Agentboxd inboxes as a sponsor-integration surface.
RESEARCH TASKS (answer each with evidence and citations):
1. Track odds: search past Devpost hackathons and winner lists — is Cybersecurity typically
   less crowded than Healthcare/Education for student hackathons? Any data or examples?
2. Prior art: find existing projects similar to "prompt-injection detection / LLM firewall /
   agent guardrails" (e.g., Lakera Guard, Rebuff, Guardrails AI, Llama Guard, Prompt Guard,
   Garak, Pyrit, OWASP LLM Top 10 resources). List what exists, what's open-source, and the
   differentiation gaps a 7-day student project can exploit.
3. Public datasets/benchmarks I can use for the detection ensemble + eval harness
   (prompt-injection datasets, phishing corpora like Enron/phishing URLs, jailbreak benchmarks).
4. Feasibility attack: find the top risks in shipping AgentSentinel in 7 days by ~1–4
   students, and concrete mitigations (scope cuts, libraries to reuse).
5. Sponsor leverage: from the sponsor descriptions above, what's the smartest, lowest-risk way
   to visibly integrate Agentboxd and Featherless into this project for judging credit?
6. Verify current facts: fetch https://www.forgehacks.dev and https://forgehacks-2026.devpost.com
   and report the EXACT track prompt text released for AI + Cybersecurity (and the other five),
   plus any timeline/rule changes.
7. Demo video: find 2–3 examples of winning AI hackathon demo videos (2–4 min) and extract the
   narrative structure that maps to the judging rubric above.
OUTPUT FORMAT: numbered answers matching tasks 1–7, each with: findings, sources (URLs), and a
one-line "so what" recommendation for the project.
