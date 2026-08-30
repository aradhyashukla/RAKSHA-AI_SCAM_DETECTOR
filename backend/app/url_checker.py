"""
url_checker.py
---------------
Real link-safety checks that go beyond "does this string contain a known
brand name." Everything here is best-effort and network-dependent, so
EVERY function degrades gracefully and returns None/neutral on failure —
a slow WHOIS server or offline demo laptop must never crash a scan or
block a request. This mirrors the same fallback philosophy as
llm_narrator.py: never let an optional enrichment step break the core
scoring flow.

Checks implemented:
    resolve_redirect_chain() - follow shortened/redirecting URLs to their
                                real final destination
    get_domain_age_days()    - WHOIS lookup; newly-registered domains are
                                a strong scam signal
    check_ssl_validity()     - does the domain present a valid, matching
                                TLS certificate
    typosquat_match()        - edit-distance check against known brand
                                domains (e.g. "sbi-online.in" vs "sbi.co.in")

All of these take a bare domain or a full URL and are individually safe
to call even if the others fail or time out.
"""

import socket
import ssl
import difflib
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT_SECONDS = 5  # fail fast — never let a slow domain hang a scan

# Legitimate root domains for common brands, used for typosquat comparison.
# Keyed by the same brand tokens used in entity_extractor.KNOWN_BRANDS so
# the two stay easy to keep in sync.
LEGIT_BRAND_DOMAINS = {
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "kotak": "kotak.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "gpay": "pay.google.com",
    "amazon": "amazon.in",
    "flipkart": "flipkart.com",
    "irctc": "irctc.co.in",
    "lic": "licindia.in",
    "epfo": "epfindia.gov.in",
    "income tax": "incometax.gov.in",
}


def resolve_redirect_chain(url: str, max_hops: int = 5) -> Optional[str]:
    """
    Follows redirects (HEAD request, falls back to GET if HEAD is blocked)
    and returns the final landing domain. This is what actually defeats
    link shorteners — flagging "bit.ly" by name is necessary but not
    sufficient, since the real danger is whatever's at the other end.
    Returns None on any network failure (timeout, DNS failure, etc.)
    rather than raising, so a dead/expired shortener doesn't crash a scan.
    """
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = requests.head(
            url, allow_redirects=True, timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"User-Agent": "Mozilla/5.0 (Raksha-ScamSentinel/1.0)"},
        )
        # Some servers don't implement HEAD properly and return 405/403;
        # retry with a lightweight GET in that case.
        if resp.status_code >= 400:
            resp = requests.get(
                url, allow_redirects=True, timeout=REQUEST_TIMEOUT_SECONDS, stream=True,
                headers={"User-Agent": "Mozilla/5.0 (Raksha-ScamSentinel/1.0)"},
            )
        final_url = resp.url
        return urlparse(final_url).netloc.lower() or None
    except requests.exceptions.RequestException:
        return None


def get_domain_age_days(domain: str) -> Optional[int]:
    """
    WHOIS lookup for domain registration date. Newly-registered domains
    (days to a few weeks old) are a strong, well-documented scam signal —
    attackers burn through disposable domains fast since they get
    blocklisted quickly. Returns None if WHOIS is unavailable, the
    'python-whois' package isn't installed, or the registrar doesn't
    expose creation date (common for some ccTLDs) — never raises.
    """
    try:
        import whois  # python-whois; imported lazily so the whole app
                       # still works if this optional dependency is missing
    except ImportError:
        return None

    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).days
        return max(age, 0)
    except Exception:
        # python-whois raises all sorts of things (socket errors, parse
        # errors, rate limits from the WHOIS server) — none of them
        # should ever break a scan.
        return None


def check_ssl_validity(domain: str) -> Optional[bool]:
    """
    Attempts a TLS handshake on port 443 and confirms the certificate's
    hostname matches. Returns True if valid, False if the cert is
    invalid/mismatched/expired, or None if the check itself couldn't be
    performed (e.g. the host doesn't even serve HTTPS — common for
    throwaway scam pages that only do plain HTTP, which is itself
    suspicious but distinct from "has a broken cert").
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                return True
    except ssl.SSLCertVerificationError:
        return False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return None


def typosquat_match(domain: str, mentioned_brand_tokens: list) -> Optional[Tuple[str, str, float]]:
    """
    Compares `domain` against the legitimate domain for each brand the
    message mentions. Catches two spoof patterns the old plain-substring
    check missed entirely:
      1. The real brand name embedded with extra junk around it, e.g.
         'sbi-onlline.in' or 'sbi-kyc-update.xyz' (contains "sbi" but
         isn't sbi.co.in) — this is the single most common Indian scam
         domain pattern.
      2. Genuine character-level typos with no clean substring match at
         all, e.g. 'hdfcbnk.com' (dropped a letter) vs 'hdfcbank.com'.

    IMPORTANT: comparison is done on each domain's first label only
    (before the first dot), not the full domain string. Comparing full
    strings directly (e.g. 'sbi-onlline.in' vs 'sbi.co.in') lets TLD/
    suffix differences like '.in' vs '.co.in' swamp the similarity score
    and mask an otherwise-obvious spoof — this was a real bug caught
    during testing (a message reading 'SBI account will be blocked...
    sbi-onlline.in' was scoring as safe because the full-string ratio
    came out to 0.60, under the 0.72 cutoff, even though the label-level
    match is unmistakable).

    Returns (brand, legit_domain, similarity_ratio) for the closest match,
    or None if nothing looks like a spoof.
    """
    domain_label = domain.split(".")[0]
    for brand in mentioned_brand_tokens:
        legit = LEGIT_BRAND_DOMAINS.get(brand)
        if not legit:
            continue
        if domain == legit or domain.endswith("." + legit):
            continue  # genuinely the real domain (or a real subdomain)

        legit_label = legit.split(".")[0]

        # Pattern 1: legit brand token embedded in the domain's label
        # with extra characters tacked on ("sbi" inside "sbi-onlline").
        if legit_label in domain_label and domain_label != legit_label:
            ratio = difflib.SequenceMatcher(None, domain_label, legit_label).ratio()
            return (brand, legit, ratio)

        # Pattern 2: character-level typo, no clean substring at all.
        ratio = difflib.SequenceMatcher(None, domain_label, legit_label).ratio()
        if ratio > 0.75:
            return (brand, legit, ratio)

    return None
