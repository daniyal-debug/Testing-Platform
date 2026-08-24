"""Detect hard-coded secrets and sensitive endpoints in extracted strings.

The patterns are intentionally high-precision (anchored formats such as AWS
access keys or Google API keys) to keep the false-positive rate low. Generic
"password="-style hits are reported at lower confidence.
"""
from __future__ import annotations

import re
from typing import List

from .models import SecretMatch

# (kind, compiled pattern, is_high_confidence)
_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"), True),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?(secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), True),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("Google OAuth Client ID", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), True),
    ("Firebase Cloud Messaging Key", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), True),
    ("Firebase Database URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), False),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), True),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), True),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), True),
    ("Stripe Publishable Key", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), False),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), True),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), True),
    ("JSON Web Token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), True),
    ("Private Key (PEM)", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), True),
    ("Generic Bearer Token", re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"), False),
    ("Generic Secret Assignment", re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token|auth)\s*[=:]\s*['\"][^'\"]{8,}['\"]"), False),
]

_CLEARTEXT_URL = re.compile(r"http://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")

# Endpoints that are harmless even over http:// (schemas, local, docs).
_URL_IGNORE = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://localhost",
    "http://127.0.0.1",
    "http://example.com",
    "http://xmlns.",
    "http://ns.",
    "http://java.sun.com",
    "http://apache.org",
    "http://android.com",
    "http://goolge.com",
)


def _preview(value: str, keep: int = 6) -> str:
    """Mask the middle of a secret so the report never re-leaks it in full."""
    value = value.strip()
    if len(value) <= keep * 2:
        return value[:2] + "…"
    return f"{value[:keep]}…{value[-4:]} ({len(value)} chars)"


def scan_strings(strings: List[str], source: str = "classes.dex") -> List[SecretMatch]:
    matches: List[SecretMatch] = []
    seen = set()
    for s in strings:
        if not s or len(s) > 4096:
            continue
        for kind, pattern, _high in _PATTERNS:
            m = pattern.search(s)
            if not m:
                continue
            key = (kind, m.group(0))
            if key in seen:
                continue
            seen.add(key)
            matches.append(SecretMatch(kind=kind, value_preview=_preview(m.group(0)), source=source))
    return matches


def find_cleartext_urls(strings: List[str], limit: int = 40) -> List[str]:
    urls = []
    seen = set()
    for s in strings:
        if "http://" not in s:
            continue
        for m in _CLEARTEXT_URL.finditer(s):
            url = m.group(0).rstrip(".,;)\"'")
            if any(url.startswith(p) for p in _URL_IGNORE):
                continue
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= limit:
                return urls
    return urls
