"""
entity_extractor.py
--------------------
Pulls structured entities out of raw message text using regex.

We deliberately use regex instead of an LLM here: entity extraction for
these specific formats (Indian phone numbers, UPI IDs, domains) is a solved
pattern-matching problem. Using an LLM would be slower, less reliable, and
harder to debug for zero benefit. Save the LLM for the parts that actually
need language understanding (Step 3).
"""

import re
from typing import List, Tuple

# Indian mobile numbers: optional +91 / 0 prefix, then 10 digits starting 6-9
PHONE_RE = re.compile(r"(?:\+91[\-\s]?|0)?([6-9]\d{9})\b")

# UPI IDs look like name@bank, e.g. john123@okhdfcbank, 9876543210@ybl
UPI_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z]{2,64})\b")

# Domains / URLs
URL_RE = re.compile(r"https?://([a-zA-Z0-9.\-]+)(?:/\S*)?", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9\-]+\.(?:com|in|net|org|xyz|info|co|link|shop)\b)", re.IGNORECASE)

# Common Indian bank / payment brand names, for spoof-detection later
KNOWN_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
    "google pay", "amazon", "flipkart", "irctc", "lic", "epfo", "income tax",
]


def extract_entities(text: str) -> List[Tuple[str, str]]:
    """
    Returns a list of (entity_type, value) tuples found in the text.
    entity_type is one of: 'phone', 'upi_id', 'domain'
    """
    entities: List[Tuple[str, str]] = []
    seen = set()

    for match in PHONE_RE.finditer(text):
        value = match.group(1)
        key = ("phone", value)
        if key not in seen:
            seen.add(key)
            entities.append(key)

    for match in UPI_RE.finditer(text):
        value = match.group(1).lower()
        # avoid false-positive: don't treat plain emails as UPI IDs unless
        # the handle looks like a known UPI bank suffix
        upi_suffixes = ("ybl", "okhdfcbank", "okaxis", "oksbi", "paytm", "upi", "ibl", "axl")
        if value.split("@")[-1] in upi_suffixes:
            key = ("upi_id", value)
            if key not in seen:
                seen.add(key)
                entities.append(key)

    for match in URL_RE.finditer(text):
        value = match.group(1).lower()
        key = ("domain", value)
        if key not in seen:
            seen.add(key)
            entities.append(key)

    for match in BARE_DOMAIN_RE.finditer(text):
        value = match.group(1).lower()
        key = ("domain", value)
        if key not in seen:
            seen.add(key)
            entities.append(key)

    return entities


def mentioned_brands(text: str) -> List[str]:
    """Returns known brand/bank names mentioned in the text (lowercased)."""
    lower = text.lower()
    return [brand for brand in KNOWN_BRANDS if brand in lower]
