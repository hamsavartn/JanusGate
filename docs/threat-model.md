# Threat model — AgentSentinel

Written to be judged: explicit assets, actors, surfaces, mitigations, and *what we do not
protect against*. Mapped to the OWASP LLM Top 10 (2025).

## Assets to protect
| Asset | Example | Protected by |
|---|---|---|
| Agent system prompt / configuration | "You are the support agent for…" | `reveal_system_prompt` rule; egress echo check; **canary tripwire** |
| Credentials reachable by the agent | API keys, tokens, session data | `secret_exfil` rule; egress credential shapes (redacted evidence) |
| Integrity of agent actions | emails sent, files deleted, payments | `tool_hijack` rule; **SentinelGuard** tool firewall |
| User data flowing through | conversation history, inbox contents | webhook/paste-site exfil rule; audit **redaction mode** |
| Trust in the agent's decisions | "why was my request blocked?" | evidence-backed verdicts; **tamper-evident audit chain** |

## Actors
1. **Remote attacker** — sends email/documents/web content designed to be read by the agent
   (indirect injection; the primary threat this project targets).
2. **Malicious/compromised user** — direct injection, jailbreaks, credential phishing of the
   agent's owner.
3. **Curious insider** — reads the audit log; mitigated by hash-chain (tamper evidence) and
   redaction mode (privacy).
4. **The upstream model itself** — hallucinated or trained-in leaks; mitigated by egress
   defense on replies (defense against your own stack).

## Attack surfaces & mitigations
| Surface | Vector | Mitigation |
|---|---|---|
| Ingress: chat | direct injection, DAN/persona, encoded payloads | heuristics (rules 1–3, 6) + semantic + LLM judges |
| Ingress: email | hidden instructions in body/footer, phishing, OTP relay | indirect-injection markers, phishing rules, **per-source policy (email threshold 4)**, mock/Agentboxd surface |
| Ingress: documents/web | footnotes, invisible characters, fake system tags, RAG poisoning | normalization (NFKC + zero-width removal), `invisible_chars` + `indirect_injection_marker` rules |
| Ingress: tools | hijacked tool args, forged function calls | `tool_hijack` rule; SentinelGuard blocks pre-execution |
| Egress: replies | system-prompt echo, credential dumps, canary exfil | `inspect_output`: canary (risk 10), credential shapes, 8-gram echo |
| Multi-turn | low-and-slow probing across turns | **session risk accumulator** (decaying score, escalation) |
| Platform (this API) | log tampering, verdict disputes | hash-chained JSONL + `/audit/verify`; feedback loop; CI regression gate |

## Explicit non-goals / residual risks (honesty)
- **No auth on this API by design** (demo scope) — deploy behind a gateway in production.
- **In-memory session state** — single-process only; multi-worker needs a shared store.
- **Rule+TF-IDF recall on novel attacks is limited** (external benchmark: recall 0.12) — the
  LLM-judge layer exists for exactly this tail; activate `GEMINI_API_KEY`.
- **No streaming support** in proxy mode; **no HTML parsing** of emails (plain-text body only).
- **Judge models can be fooled**; the ensemble's corroboration rules limit, but do not
  eliminate, adversarial evasion. Security is a process; the feedback loop is part of it.
