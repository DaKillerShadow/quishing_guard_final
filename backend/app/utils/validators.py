"""validators.py — Request input validation."""
import re
from urllib.parse import urlparse

# QR payloads that are NOT URLs (skip URL analysis)
# Kept strictly lowercase for case-insensitive matching
_NON_URL_PREFIXES = (
    "wifi:", "begin:vcard", "begin:vcalendar",
    "matmsg:", "tel:", "sms:", "geo:", "mailto:",
    "smsto:", "mms:", "bitcoin:", "ethereum:", "litecoin:",
)

# Supported URL schemes
_ALLOWED_SCHEMES = frozenset({"http", "https"})

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

    # Case-insensitive prefix check to catch "WiFi:", "WIFI:", etc.
    if payload.lower().startswith(_NON_URL_PREFIXES):
        return False, "Non-URL QR payload type detected (e.g., WIFI, vCard). Analysis not applicable."

    try:
        parsed = urlparse(payload)
        
        # Safely normalize: add scheme only if the parser confirms no scheme exists.
        # This prevents bypassing the allowlist with strings like 'javascript:alert(1)'
        if not parsed.scheme:
            payload = "https://" + payload
            parsed = urlparse(payload)
            
    except ValueError:
        return False, "Malformed URL — unable to parse."

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http/https are analysed."

    if not parsed.netloc:
        return False, "URL has no host component."

    return True, ""
