"""Layer 1 — heuristic scanner.

Fast, deterministic, always-on. Catches obvious attack patterns and produces
severity-weighted hits. The LLM judge (layer 3) covers everything the rules miss.

Input is normalized before scanning (NFKC + zero-width character removal) so
obfuscation via invisible characters cannot smuggle phrases past the rules.
"""
import re
import unicodedata

from backend.schemas import HeuristicHit

# Zero-width / invisible characters used to split keywords invisibly.
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\xad]")


def normalize_for_scan(text: str) -> str:
    """NFKC normalization + invisible-character removal (deterministic, lossy-safe)."""
    return _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", text))

# (rule_id, category, regex, severity 0-10, explanation)
RULES: list[tuple[str, str, re.Pattern, int, str]] = [
    (
        "ignore_instructions",
        "injection",
        re.compile(
            r"ignore (all |any |the above |previous |prior |earlier )+(instructions|prompts?|rules?|directions?)"
            r"|(disregard|forget) (all |any |the )?(above|previous|prior|earlier|your) ?(instructions|prompts?|rules?)"
            r"|(disregard|forget) everything (you|before|above|so far|i)",
            re.IGNORECASE,
        ),
        9,
        "Classic direct prompt injection: tries to nullify the agent's real instructions.",
    ),
    (
        "reveal_system_prompt",
        "exfiltration",
        re.compile(
            r"(reveal|show|print|repeat|output|display|tell me|what is|what's|share) ?(me )?(your|the) "
            r"(system prompt|system instructions|initial (prompt|instructions)|hidden (prompt|instructions)|developer message)|"
            r"what (were|are) you (told|instructed|programmed) (to do|with)",
            re.IGNORECASE,
        ),
        8,
        "Attempts to exfiltrate the agent's system prompt / hidden configuration.",
    ),
    (
        "role_override",
        "injection",
        re.compile(
            r"(system|new|updated?|revised) (prompt|instructions?|rules?|directives?)\b\s*[:\-]?|"
            r"you are now (a|an|no longer)|"
            r"act as (if you were )?(a|an) (unfiltered|unrestricted|uncensored|DAN)|"
            r"(pretend|imagine|assume) (that )?(your|the) (instructions|rules|guidelines|prompts?) (do not|don't|doesn't) exist",
            re.IGNORECASE,
        ),
        8,
        "Tries to redefine the agent's identity, replace its rules, or negate its instructions.",
    ),
    (
        "jailbreak_persona",
        "jailbreak",
        re.compile(
            r"\bDAN\b|do anything now|jailbreak|"
            r"(enable|enter|activate|turn on|switch to|go into) developer mode|"
            r"no (ethical |moral |safety )?(restrictions|filters|limits|guardrails|ethics|morals|rules|guidelines|boundaries)|"
            r"bypass (your|the|these) (own )?(content )?(filters?|guardrails?|restrictions?)|"
            r"operate without (restrictions|limits|filters|guardrails|rules|supervision)",
            re.IGNORECASE,
        ),
        7,
        "Known jailbreak framing (DAN / developer mode / restriction removal / filter bypass).",
    ),
    (
        "tool_hijack",
        "tool_hijack",
        re.compile(
            r"(call|invoke|use|run|execute) the ([a-z_]{2,30} ?){0,3}(tool|function|command|api)|"
            r"(send|email|transfer|delete|post) (all |the |this )?(money|funds|file|files|data|message|email)s? ?(to|from)?",
            re.IGNORECASE,
        ),
        7,
        "Instructs the agent to invoke tools or perform side-effecting actions — dangerous if "
        "the text is not from a trusted user.",
    ),
    (
        "encoded_payload",
        "injection",
        re.compile(
            r"(decode|execute|follow) (the |this |following )?(base64|rot13|hex|encoded) ?(instruction|message|command|text)?|"
            r"\b[A-Za-z0-9+/]{60,}={0,2}\b",
            re.IGNORECASE,
        ),
        6,
        "Encoded payloads are a common way to smuggle instructions past filters.",
    ),
    (
        "indirect_injection_marker",
        "injection",
        re.compile(
            r"\[?system\]|\[INST\]|<<SYS>>|</?(assistant|system)>|###\s*(system|instruction)s?\s*:|"
            r"\b(system|assistant)\s+(note|message|notice)\b|"
            r"end of (the )?(user )?(input|turn|message)|begin (new )?(system )?(prompt|instructions)",
            re.IGNORECASE,
        ),
        7,
        "Fake chat-role markers / system tags embedded in content (typical indirect injection "
        "found in emails, documents, and web pages).",
    ),
    (
        "multilingual_injection",
        "injection",
        re.compile(
            r"ignor(e|ez|es)\s+(toutes?\s+|les\s+|tes\s+|vos\s+)*(instructions?|directives?)\s+(précédentes?|antérieures?)|"
            r"donne(-|\s)?moi\s+(ton|votre)\s+(prompt|instructions?)\s+(système|systeme)|"
            r"ignora\s+(todas?\s+|las\s+)*(instrucciones|indicaciones)\s+(anteriores|previas)|"
            r"ignore\s+(todas?\s+|as\s+)*(instruções|instrucciones)\s+(anteriores|prévias)|"
            r"ignoriere\s+(alle\s+)?(bisherigen\s+|vorherigen\s+)?anweisungen|"
            r"игнорир(уй|овать|уйте)\s+(все\s+)?(предыдущие|прежние)\s+(инструкции|указания)|"
            r"忽略(之前|以前|所有)?(的)?(指令|指示)|以前の指示を無視|"
            r"पिछले\s*(निर्देश|हिदायतें)\s*(को)?\s*नज़रअंदाज|"
            r"अपने पिछले निर्देश",
            re.IGNORECASE,
        ),
        8,
        "High-signal non-English prompt-injection phrases (FR/ES/PT/DE/RU/ZH/JA/HI).",
    ),
    (
        "suspicious_url",
        "phishing",
        re.compile(
            r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"            # IP-literal host
            r"https?://[^/\s]*xn--|"                                      # punycode host
            r"https?://([^/\s]+\.)+([^/\s]+)[/\s][^\s]{40,}",             # very long path
            re.IGNORECASE,
        ),
        5,
        "URL with risk shape (IP-literal host, punycode, or unusually long path) — "
        "common in phishing; verify the destination.",
    ),
    (
        "secret_exfil",
        "exfiltration",
        re.compile(
            r"(api[ _-]?key|password|passwd|secret|token|credential|private key|ssh key)\s*[:=]\s*\S+|"
            r"(repeat|print|reveal|show|send|post|upload|forward|list|output) (the |all |this |your |me |every |each )?(above )?"
            r"(api ?keys?|passwords?|secrets?|tokens?|credentials?|conversation|chat history|environment variables?|env vars)",
            re.IGNORECASE,
        ),
        9,
        "Requests to capture or forward secrets / conversation history — exfiltration attempt.",
    ),
    (
        "webhook_exfil",
        "exfiltration",
        re.compile(
            r"https?://[^\s]*(webhook|requestcatcher|pipedream|ngrok|pastebin|hastebin|discord\.com/api/webhooks)[^\s]*",
            re.IGNORECASE,
        ),
        8,
        "Message contains a common exfiltration endpoint (webhook / paste site / tunnel).",
    ),
    (
        "phishing_urgency_creds",
        "phishing",
        re.compile(
            r"(urgent|immediately|within \d+ ?(hours|days)|final (warning|notice)|account (will be )?(suspended|closed|locked|deactivated)).*"
            r"(verify|confirm|validate|update|unlock|restore)|"
            r"(verify|confirm|validate|update|unlock|restore).*"
            r"(urgent|immediately|within \d+ ?(hours|days)|final (warning|notice)|suspended|deactivated|interrupted)|"
            r"(verify|confirm|update) (your )?(account|identity|billing|payment|password|login) (now|immediately|here)|"
            r"(pay|settle)[^!?\n]{0,40}(release|delivery|customs|unlock|verification|processing)\s+(fee|charge|payment)",
            re.IGNORECASE,
        ),
        8,
        "Phishing pattern: urgency pressure combined with a credential/verification ask (either "
        "order), or a pay-a-fee-to-unlock demand.",
    ),
    (
        "phishing_otp",
        "phishing",
        re.compile(
            r"(enter|send|share|give) (me |us )?(the )?(code|otp|one[- ]time (code|password)|verification code)|"
            r"(we |we've )?(sent|sending) you a (code|otp)",
            re.IGNORECASE,
        ),
        8,
        "Solicits one-time codes / OTPs — a classic account-takeover move.",
    ),
    (
        "url_shortener",
        "phishing",
        re.compile(
            r"https?://(bit\.ly|tinyurl\.com|t\.co/|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|shorturl\.at)/\S+",
            re.IGNORECASE,
        ),
        5,
        "Shortened URL hides the true destination — common in phishing, verify before trusting.",
    ),
]

BENIGN_MAX_PER_RULE = 2  # cap snippets per rule to keep output clean


def scan(text: str) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    # Flag invisible characters on the RAW text (normalization would erase the evidence).
    # Severity 3: alone this is informational (real-world text often contains stray
    # zero-widths from copy-paste); hidden PHRASES still get caught by the normalized
    # re-scan, so this hit only adds context boost alongside real rules.
    if _INVISIBLE_RE.search(text):
        hits.append(HeuristicHit(
            rule="invisible_chars", category="injection", severity=3,
            snippet="(zero-width/invisible characters present)",
            explanation="Zero-width/invisible characters — a common trick to smuggle or "
                        "obfuscate instructions (normalized text is also re-scanned, so "
                        "hidden phrases still surface).",
        ))
    text = normalize_for_scan(text)
    for rule_id, category, pattern, severity, explanation in RULES:
        count = 0
        for m in pattern.finditer(text):
            snippet = m.group(0).strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append(
                HeuristicHit(
                    rule=rule_id, category=category, severity=severity,
                    snippet=snippet, explanation=explanation,
                )
            )
            count += 1
            if count >= BENIGN_MAX_PER_RULE:
                break
    return hits


def heuristic_risk(hits: list[HeuristicHit]) -> int:
    """Highest severity wins; a second hit in a different category adds a small boost."""
    if not hits:
        return 0
    top = max(h.severity for h in hits)
    categories = {h.category for h in hits}
    return min(10, top + (1 if len(categories) > 1 else 0))
