"""
scorer.py
---------
The deterministic rule-based scoring engine. This is the piece that
actually decides the risk score - the LLM (Step 3) only explains it in
plain language afterward. See the whiteboard note: Approach B was chosen
over "let the LLM decide" specifically so this stays fast, debuggable,
and defensible when judges ask "how does it work."

Each rule returns (points, name, description) or None if it didn't fire.
Score is clamped to 0-100. Verdict bands:
    0-29   -> safe
    30-64  -> suspicious
    65-100 -> dangerous
"""

import re
from typing import List, Tuple, Optional, Dict
from app.entity_extractor import mentioned_brands

# --- Rule definitions -------------------------------------------------

URGENCY_PHRASES = [
    "act now", "immediately", "within 24 hours", "account will be blocked",
    "account suspended", "verify now", "last warning", "urgent", "expire today",
    "limited time", "click immediately", "kyc update", "kyc expire",
    "block your account", "final notice", "verify your account",
    "unusual activity", "suspicious activity", "restricted", "reactivate",
    "will be deactivated", "act immediately", "response is required",
    # Hinglish / Hindi-transliterated equivalents — a huge share of real
    # Indian scam SMS/WhatsApp messages mix English and Hindi, and the
    # pure-English phrase list above misses almost all of them.
    "turant", "abhi karein", "jaldi karein", "account band ho jayega",
    "khata band", "aakhri chetavani", "24 ghante", "abhi verify karein",
]

MONEY_REQUEST_PHRASES = [
    "send money", "pay now", "processing fee", "refund pending", "claim your prize",
    "you have won", "lottery", "advance fee", "registration fee", "security deposit",
    "transfer fee", "unlock your", "gift card",
    # Refund / overpayment scams — a very common template ("we sent you too
    # much, click here to send the difference back") that plain-jargon
    # phrase lists like the ones above never caught.
    "overpaid", "overpayment", "overcharged", "excess payment",
    "process your refund", "process the refund", "refund of", "refund amount",
    "you have received a refund", "eligible for a refund", "claim your refund",
    # Hinglish equivalents
    "paisa bhejo", "paise bhejo", "inaam jeeta", "lottery jeeta",
    "advance paisa", "processing charge", "refund pane ke liye",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "cutt.ly", "shorturl.at", "t.co", "is.gd",
    "rebrand.ly", "rb.gy", "tiny.cc",
]

JOB_SCAM_PHRASES = [
    "work from home", "earn per day", "no experience needed", "part time job",
    "daily payout", "join telegram group", "task based job", "earn ",
    "ghar baithe kamayein", "roz ka payment", "daily income",
]

CTA_PHRASES = ["click here", "click below", "tap here", "click this link", "click the link below"]

RISKY_TLDS = (".xyz", ".top", ".info", ".link", ".shop", ".click")


def _contains_any(text_lower: str, phrases: List[str]) -> List[str]:
    return [p for p in phrases if p in text_lower]


def rule_urgency_language(text_lower: str) -> Optional[Tuple[int, str, str]]:
    hits = _contains_any(text_lower, URGENCY_PHRASES)
    if hits:
        return (15, "urgency_language", f"Uses urgency/pressure language ({hits[0]!r})")
    return None


def rule_money_request(text_lower: str) -> Optional[Tuple[int, str, str]]:
    hits = _contains_any(text_lower, MONEY_REQUEST_PHRASES)
    if hits:
        return (20, "money_request", f"Requests payment or promises money ({hits[0]!r})")
    return None


def rule_shortened_url(text_lower: str) -> Optional[Tuple[int, str, str]]:
    hits = [d for d in SHORTENER_DOMAINS if d in text_lower]
    if hits:
        return (20, "shortened_url", f"Contains a link-shortener domain ({hits[0]}), destination is hidden")
    return None


def rule_brand_domain_mismatch(text_lower: str, domains: List[str]) -> Optional[Tuple[int, str, str]]:
    """
    If the message mentions a known brand (e.g. 'SBI', 'Paytm') but the
    linked domain doesn't contain that brand name, it's a classic spoof
    pattern (e.g. 'sbi-kyc-update.xyz' impersonating sbi.co.in).
    """
    brands = mentioned_brands(text_lower)
    if not brands or not domains:
        return None
    for brand in brands:
        brand_token = brand.replace(" ", "")
        for domain in domains:
            if brand_token in domain:
                return None  # legit-looking match found, don't flag
    return (25, "brand_domain_mismatch",
            f"Mentions brand(s) {brands} but linked domain(s) {domains} don't match")


def rule_job_scam_pattern(text_lower: str) -> Optional[Tuple[int, str, str]]:
    hits = _contains_any(text_lower, JOB_SCAM_PHRASES)
    if len(hits) >= 2:
        return (15, "job_scam_pattern", f"Matches common fake-job-offer phrasing ({hits[:2]})")
    return None


def rule_vague_cta_no_destination(text_lower: str, domains: List[str]) -> Optional[Tuple[int, str, str]]:
    """
    Messages that say 'click here' / 'tap here' but contain no actual URL
    or domain are a common scam pattern (the real destination is hidden or
    only revealed once you tap). Legitimate transactional messages almost
    always show the real link. Without this rule, a message with vague
    CTA wording and no link fell through every other rule untouched.
    """
    if domains:
        return None
    hits = _contains_any(text_lower, CTA_PHRASES)
    if hits:
        return (15, "vague_cta_no_destination",
                f"Asks you to {hits[0]!r} but includes no visible link or domain to verify")
    return None


def rule_suspicious_tld(text_lower: str, domains: List[str]) -> Optional[Tuple[int, str, str]]:
    hits = [d for d in domains if d.endswith(RISKY_TLDS)]
    if hits:
        return (10, "suspicious_tld", f"Domain uses a high-abuse TLD ({hits[0]})")
    return None


def rule_qr_upi_mismatch(source: str, text_lower: str) -> Optional[Tuple[int, str, str]]:
    """
    QR-specific check: a decoded UPI payment QR should contain a 'pn='
    (payee name) parameter matching the claimed sender. If the QR source
    lacks any recognizable UPI structure entirely, that's itself odd for
    a 'scan to pay' QR - flag it as unverifiable.
    """
    if source == "qr" and "upi://" in text_lower and "pn=" not in text_lower:
        return (10, "qr_missing_payee_name", "QR payment link has no verifiable payee name field")
    return None


# Known legitimate UPI handle suffixes (bank/PSP-issued). A VPA with a
# suffix NOT in this list is not necessarily fraud, but it's unusual
# enough (most scam QR kits use throwaway/rare handles) to add a small
# amount of suspicion rather than blindly trusting any '@xyz' as UPI.
KNOWN_UPI_HANDLES = {
    "ybl", "oksbi", "okhdfcbank", "okaxis", "okicici", "paytm", "upi",
    "ibl", "axl", "apl", "jio", "airtel", "freecharge", "yesbank",
}


def rule_qr_upi_unknown_handle(qr_parsed: Optional[dict]) -> Optional[Tuple[int, str, str]]:
    """
    Runs only on decoded transaction QR payloads (see /analyze/qr).
    Flags a payee VPA whose bank handle isn't one of the common,
    recognized PSP suffixes — a soft signal, not proof of fraud, so it
    carries a modest weight on its own but stacks with threat-graph hits.
    """
    if not qr_parsed or not qr_parsed.get("payee_vpa"):
        return None
    vpa = qr_parsed["payee_vpa"]
    if "@" not in vpa:
        return (15, "qr_malformed_vpa", f"QR payee VPA '{vpa}' is not a valid UPI ID format")
    handle = vpa.split("@")[-1].lower()
    if handle not in KNOWN_UPI_HANDLES:
        return (10, "qr_unrecognized_handle",
                f"QR payee VPA uses an uncommon bank handle '@{handle}' — verify before paying")
    return None


def rule_qr_missing_amount(source: str, qr_parsed: Optional[dict]) -> Optional[Tuple[int, str, str]]:
    """
    A dynamic 'scan and pay' QR with NO amount field lets the payee
    (attacker) prompt the user to type in any amount manually — a known
    trick to get victims to enter a much larger amount than they intended.
    Static merchant QRs legitimately omit amount too, so this is a small,
    non-decisive signal, not a hard block.
    """
    if source == "qr" and qr_parsed and not qr_parsed.get("amount"):
        return (5, "qr_no_fixed_amount",
                "QR does not specify a fixed amount — you'll be prompted to type one in, verify it matches what you expect")
    return None


# --- Real link-safety rules (fed by app/url_checker.py results) --------
# main.py runs the network-dependent checks in url_checker.py BEFORE
# calling score_message() and passes the results in as `url_checks`, a
# dict keyed by domain: { domain: {"redirect_to": str|None,
# "domain_age_days": int|None, "ssl_valid": bool|None,
# "typosquat": (brand, legit_domain, ratio)|None} }
# Every field is optional/None-safe since these checks are best-effort
# and network-dependent (see url_checker.py's own docstring).

def rule_typosquat_domain(url_checks: Optional[Dict[str, dict]]) -> Optional[Tuple[int, str, str]]:
    if not url_checks:
        return None
    for domain, info in url_checks.items():
        ts = info.get("typosquat")
        if ts:
            brand, legit_domain, ratio = ts
            return (30, "typosquat_domain",
                    f"'{domain}' looks like a lookalike of '{legit_domain}' ({brand}) — "
                    f"{ratio:.0%} character similarity but not the real domain")
    return None


def rule_new_domain(url_checks: Optional[Dict[str, dict]]) -> Optional[Tuple[int, str, str]]:
    if not url_checks:
        return None
    for domain, info in url_checks.items():
        age = info.get("domain_age_days")
        if age is not None and age < 30:
            return (20, "newly_registered_domain",
                    f"Domain '{domain}' was registered only {age} day(s) ago — "
                    f"scam sites are usually thrown away and replaced quickly")
    return None


def rule_invalid_ssl(url_checks: Optional[Dict[str, dict]]) -> Optional[Tuple[int, str, str]]:
    if not url_checks:
        return None
    for domain, info in url_checks.items():
        if info.get("ssl_valid") is False:
            return (15, "invalid_ssl_cert",
                    f"Domain '{domain}' presents an invalid or mismatched security certificate")
    return None


def rule_redirect_to_different_domain(url_checks: Optional[Dict[str, dict]]) -> Optional[Tuple[int, str, str]]:
    """
    Flags when a shortened/redirecting link's REAL final destination is a
    different, unrelated domain than what was visible in the message —
    the core trick link shorteners are used for in scams. This only fires
    when we actually resolved a redirect chain (see url_checker.py); if
    the request failed or timed out, url_checks won't have a redirect_to
    value and this rule silently stays quiet rather than guessing.
    """
    if not url_checks:
        return None
    for domain, info in url_checks.items():
        final = info.get("redirect_to")
        if final and final != domain and domain in SHORTENER_DOMAINS:
            return (15, "redirect_destination",
                    f"'{domain}' actually redirects to '{final}' — verify that destination before trusting it")
    return None


# --- Orchestration ------------------------------------------------------

def score_message(
    text: str,
    source: str,
    domains: List[str],
    threat_graph_hits: List[dict],
    qr_parsed: Optional[dict] = None,
    url_checks: Optional[Dict[str, dict]] = None,
) -> dict:
    """
    Runs all rules, adds threat-graph boosts, and returns a full breakdown.
    threat_graph_hits: list of {entity_type, value, report_count} from
                        threat_graph.lookup_entities()
    qr_parsed: only set when source == 'qr' and the QR decoded to a UPI
               payment link (see qr_processor.parse_upi_link)
    url_checks: optional dict of real link-safety results from
                app/url_checker.py, keyed by domain (see that module).
    """
    text_lower = text.lower()
    triggered = []
    score = 0

    rule_results = [
        rule_urgency_language(text_lower),
        rule_money_request(text_lower),
        rule_shortened_url(text_lower),
        rule_brand_domain_mismatch(text_lower, domains),
        rule_job_scam_pattern(text_lower),
        rule_vague_cta_no_destination(text_lower, domains),
        rule_suspicious_tld(text_lower, domains),
        rule_qr_upi_mismatch(source, text_lower),
        rule_qr_upi_unknown_handle(qr_parsed),
        rule_qr_missing_amount(source, qr_parsed),
        rule_typosquat_domain(url_checks),
        rule_new_domain(url_checks),
        rule_invalid_ssl(url_checks),
        rule_redirect_to_different_domain(url_checks),
    ]

    for result in rule_results:
        if result:
            points, name, description = result
            score += points
            triggered.append({"name": name, "description": description, "weight": points})

    # Threat graph boost: previously-reported entities add weight
    # proportional to how many times they've been reported, capped so a
    # single wildly-over-reported entity can't single-handedly max the score.
    for hit in threat_graph_hits:
        if hit["report_count"] > 0:
            boost = min(hit["report_count"] * 8, 40)
            score += boost
            triggered.append(
                {
                    "name": "threat_graph_match",
                    "description": (
                        f"{hit['entity_type']} '{hit['value']}' was reported "
                        f"{hit['report_count']} time(s) before by other users"
                    ),
                    "weight": boost,
                }
            )

    score = max(0, min(100, score))

    if score < 30:
        verdict = "safe"
    elif score < 65:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    return {"risk_score": score, "verdict": verdict, "triggered_rules": triggered}
