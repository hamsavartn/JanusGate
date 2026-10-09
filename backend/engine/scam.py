"""Scam & impersonation analysis — the consumer-facing layer of JanusGate.

The track prompt asks for solutions that help PEOPLE recognize, prevent, verify, or
respond to scams, impersonation, and fraud. This module produces a per-message
SCAM-SIGNAL REPORT: which fraud signals fired, the likely scam archetype, an overall
risk, and a safe-response recommendation — written for the message's human recipient,
not just for the machine.

Signals detected here (weights sum into a 0-10 risk):
  - brand impersonation: display name claims a brand the sender domain is not
  - lookalike domains: typosquat / homoglyph / brand-in-host with wrong TLD
  - free-mail claiming corporate identity
  - urgency pressure, credential solicitation, OTP relay, payment/gift-card/crypto
    demands, too-good-to-be-true offers, authority pressure
"""
import re
import unicodedata
from urllib.parse import urlparse

from pydantic import BaseModel, Field

# brand -> official registrable domains (suffix match on registrable part)
BRAND_DOMAINS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "outlook.com", "live.com", "msn.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"},
    "google": {"google.com", "accounts.google.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "meta": {"meta.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "hsbc": {"hsbc.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "steam": {"steampowered.com"},
    "office365": {"office.com", "office365.com"},
    "dropbox": {"dropbox.com"},
    "revolut": {"revolut.com"},
}

BRAND_RE = re.compile(
    r"\b(" + "|".join(sorted(BRAND_DOMAINS, key=len, reverse=True)) + r")\b", re.IGNORECASE
)

FREEMAIL = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "aol.com", "icloud.com",
            "proton.me", "protonmail.com", "mail.ru", "yandex.com", "gmx.com"}

_LEET_DOMAIN = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "7": "t"})

_SENDER_RE = re.compile(r"^(?P<name>[^<]*?)?<?(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?$")


class ScamSignal(BaseModel):
    signal: str
    detail: str
    weight: int = Field(ge=0, le=6)


class ScamReport(BaseModel):
    """Per-message fraud report for the human recipient."""
    is_scam_risk: bool
    risk: int = Field(ge=0, le=10)
    scam_type: str = Field(
        description="bec_ceo_fraud | otp_relay | gift_card | tech_support | lottery_prize | "
                    "crypto_payment | invoice | phishing_generic | none")
    signals: list[ScamSignal]
    impersonated_brand: str | None = None
    advised_action: str = Field(
        description="delete_and_report | verify_via_official_channel | do_not_click | none")
    advice: str


def _registrable(host: str) -> str:
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _domain_impersonates(domain: str, brand: str) -> str | None:
    """Return a reason string if `domain` impersonates `brand`, else None."""
    official = BRAND_DOMAINS[brand]
    d = domain.lower()
    reg = _registrable(d)
    if any(reg == o or reg.endswith("." + o) or d.endswith("." + o) for o in official):
        return None
    # brand keyword embedded in the host (microsoft-verify.example, secure.paypa1.com)
    if brand in re.sub(r"[^a-z]", "", d):
        # leet-unmap and re-check against official
        if _registrable(d.translate(_LEET_DOMAIN)) not in official:
            return f"brand '{brand}' embedded in unofficial domain '{domain}'"
    # typosquat: edit distance to an official registrable domain
    for o in official:
        o_reg = _registrable(o)
        if abs(len(reg) - len(o_reg)) <= 2 and _levenshtein(reg, o_reg) <= 2:
            return f"'{domain}' is a near-match (edit distance) to official '{o}'"
    return None


def _urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>)\]]+", text, re.IGNORECASE)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _guessed_scatype(text_lower: str, signals: list[ScamSignal]) -> str:
    has = lambda *ws: any(w in text_lower for w in ws)
    if has("gift card", "giftcard") and has("won", "prize", "claim"):
        return "gift_card"
    if has("verification code", "otp", "one-time", "one time code", "read it back"):
        return "otp_relay"
    if has("wire transfer", "invoice", "process this payment", "bank details"):
        return "bec_ceo_fraud" if has("ceo", "confidential", "urgent", "in a meeting") else "invoice"
    if has("bitcoin", "crypto", "wallet address"):
        return "crypto_payment"
    if has("you won", "lottery", "prize", "reward", "claim your"):
        return "lottery_prize"
    if has("virus detected", "your account is hacked", "call support", "technical support"):
        return "tech_support"
    if any(s.signal.startswith("impersonation") for s in signals) or has(
            "verify your account", "suspended", "login", "password"):
        return "phishing_generic"
    return "phishing_generic" if len(signals) >= 2 else "none"


_ADVICE = {
    "bec_ceo_fraud": (
        "verify_via_official_channel",
        "Verify with the claimed sender using a phone number or channel you already have — "
        "never the one in this message. Unexpected payment/urgent requests impersonating "
        "executives are the classic BEC scam."),
    "otp_relay": (
        "delete_and_report",
        "No legitimate service will ask you to read back a one-time code. Sharing it hands "
        "over your account. Delete and report."),
    "gift_card": (
        "delete_and_report",
        "Real prizes never require payment or your card details. This is a classic "
        "gift-card scam — delete and report."),
    "tech_support": (
        "delete_and_report",
        "Real companies don't cold-warn you about viruses and demand remote access. "
        "Delete; contact the company directly if unsure."),
    "lottery_prize": (
        "delete_and_report",
        "'You won' messages that ask for details or fees are lottery scams. Delete."),
    "crypto_payment": (
        "delete_and_report",
        "Any demand for crypto payment is near-certainly irreversible fraud. Delete and "
        "report."),
    "invoice": (
        "verify_via_official_channel",
        "Check this invoice against the vendor's official portal or a known contact before "
        "paying anything."),
    "phishing_generic": (
        "do_not_click",
        "Don't click links or enter credentials from this message. If it claims to be a "
        "service you use, open their app/site directly instead."),
    "none": ("none", "No strong scam signals found — stay alert with links and attachments."),
}


def build_scam_report(text: str, sender: str | None = None) -> ScamReport:
    text = unicodedata.normalize("NFKC", text)
    lower = text.lower()
    signals: list[ScamSignal] = []
    impersonated: str | None = None

    # --- sender impersonation ---
    if sender:
        m = _SENDER_RE.match(sender.strip())
        if m:
            email = (m.group("email") or "").lower()
            display = (m.group("name") or "").strip()
            domain = email.split("@", 1)[1] if "@" in email else ""
            claimed = set(b.lower() for b in BRAND_RE.findall(display))
            for brand in claimed:
                reason = _domain_impersonates(domain, brand) if domain else "no sender domain"
                if reason:
                    impersonated = impersonated or brand
                    signals.append(ScamSignal(
                        signal=f"impersonation:{brand}", detail=reason, weight=4))
            if domain in FREEMAIL and claimed:
                impersonated = impersonated or sorted(claimed)[0]
                signals.append(ScamSignal(
                    signal="impersonation:freemail",
                    detail=f"claims brand identity ({', '.join(sorted(claimed))}) but sent "
                           f"from free mail ({domain})", weight=4))

    # --- URLs embedding brands on unofficial hosts ---
    for url in _urls(text):
        host = _host(url)
        if not host:
            continue
        for brand in set(b.lower() for b in BRAND_RE.findall(host)):
            reason = _domain_impersonates(host, brand)
            if reason:
                impersonated = impersonated or brand
                signals.append(ScamSignal(
                    signal=f"impersonation:{brand}", detail=f"link: {reason}", weight=4))
                break

    # --- classic fraud-pressure signals ---
    if re.search(r"\b(urgent|immediately|within \d+ ?(hours|days)|final (warning|notice)|"
                 r"act now|last chance)\b", lower):
        signals.append(ScamSignal(signal="urgency_pressure",
                                  detail="pressure to act fast — a core scam tactic", weight=2))
    if re.search(r"\b(password|login|credentials|verify your account|confirm your (account|"
                 r"identity|payment|details))\b", lower):
        signals.append(ScamSignal(signal="credential_solicitation",
                                  detail="asks for login/credential confirmation", weight=3))
    if re.search(r"\b(otp|one[- ]time (code|password)|verification code|read it back)\b", lower):
        signals.append(ScamSignal(signal="otp_solicitation",
                                  detail="asks you to share a one-time code", weight=4))
    if re.search(r"\b(wire transfer|make the payment|process this payment|gift card|"
                 r"crypto|bitcoin|release fee|processing fee)\b", lower):
        signals.append(ScamSignal(signal="payment_demand",
                                  detail="pushes an urgent or unusual payment", weight=3))
    if re.search(r"\b(you (have )?won|lottery|prize|exclusive reward|claim your)\b", lower):
        signals.append(ScamSignal(signal="too_good_to_be_true",
                                  detail="unexpected prize/reward framing", weight=2))
    if re.search(r"\b(ceo|director|cfo|confidential|keep this (between|secret)|"
                 r"don't tell|i'm in a meeting)\b", lower):
        signals.append(ScamSignal(signal="authority_secrecy",
                                  detail="authority + secrecy pressure (BEC pattern)", weight=3))
    for url in _urls(text):
        host = _host(url)
        if host and re.search(r"\.(xyz|top|ru|click|shop|live)\b", host):
            signals.append(ScamSignal(signal="high_risk_tld",
                                      detail=f"link host '{host}' uses a TLD common in abuse",
                                      weight=2))
            break

    risk = min(10, sum(s.weight for s in signals))
    is_scam_risk = risk >= 4
    scam_type = _guessed_scatype(lower, signals) if is_scam_risk else "none"
    action, advice = (_ADVICE[scam_type] if is_scam_risk else _ADVICE["none"])
    if impersonated:
        advice = f"Possible impersonation of '{impersonated}'. " + advice
    return ScamReport(
        is_scam_risk=is_scam_risk, risk=risk, scam_type=scam_type, signals=signals,
        impersonated_brand=impersonated, advised_action=action, advice=advice)
