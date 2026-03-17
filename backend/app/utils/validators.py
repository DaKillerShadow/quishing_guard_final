"""validators.py — Request input validation."""
import re
from urllib.parse import urlparse


# QR payloads that are NOT URLs (skip URL analysis)
_NON_URL_PREFIXES = (
    "WIFI:", "wifi:", "BEGIN:VCARD", "BEGIN:VCALENDAR",
    "MATMSG:", "tel:", "sms:", "geo:", "mailto:",
    "smsto:", "mms:", "bitcoin:", "ethereum:", "litecoin:",
)

# Supported URL schemes
_ALLOWED_SCHEMES = {"http", "https"}

# Max URL length (WHATWG recommends ≤ 2083 for IE compat; we're generous)
MAX_URL_LEN = 8192


def validate_url_payload(payload: str) -> tuple[bool, str]:
    """
    Validate a QR-decoded URL payload before analysis.

    Returns:
        (is_valid: bool, reason: str)  — reason is '' when valid.
    """
    if not payload or not isinstance(payload, str):
        return False, "Payload must be a non-empty string."

    payload = payload.strip()

    if len(payload) > MAX_URL_LEN:
        return False, f"Payload exceeds maximum length of {MAX_URL_LEN} characters."

    if payload.startswith(_NON_URL_PREFIXES):
        return False, f"Non-URL QR payload type detected (e.g., WIFI, vCard). Analysis not applicable."

    # Normalise: add scheme only if no scheme present at all.
    # Using "://" avoids prepending https:// onto schemes like ftp://, which
    # would produce "https://ftp://…" and cause urlparse to read the scheme
    # as "https", silently bypassing the scheme allowlist check below.
    if "://" not in payload:
        payload = "https://" + payload

    try:
        parsed = urlparse(payload)
    except Exception:
        return False, "Malformed URL — unable to parse."

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http/https are analysed."

    if not parsed.netloc:
        return False, "URL has no host component."

    return True, ""
