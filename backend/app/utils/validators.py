"""validators.py — Request input validation."""
import re
from urllib.parse import urlparse

_NON_URL_PREFIXES = (
    "wifi:", "begin:vcard", "begin:vcalendar",
    "matmsg:", "tel:", "sms:", "geo:", "mailto:",
    "smsto:", "mms:", "bitcoin:", "ethereum:", "litecoin:",
)

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# AUDIT FIX [ENG-17]: QR code standard ISO 18004 limits alphanumeric payloads
# to 4,296 characters. Accepting 8,192 bytes allowed non-QR-origin payloads
# to reach the parser, widening the fuzzing surface unnecessarily.
MAX_URL_LEN = 4296  # ISO 18004 maximum alphanumeric QR payload length


def validate_url_payload(payload: str) -> tuple[bool, str]:
    """
    Validate a QR-decoded URL payload before analysis.
    Returns (is_valid: bool, reason: str) — reason is '' when valid.
    """
    if not payload or not isinstance(payload, str):
        return False, "Payload must be a non-empty string."

    payload = payload.strip()

    if len(payload) > MAX_URL_LEN:
        return False, f"Payload exceeds maximum length of {MAX_URL_LEN} characters (ISO 18004)."

    if payload.lower().startswith(_NON_URL_PREFIXES):
        return False, "Non-URL QR payload type detected (e.g., WIFI, vCard). Analysis not applicable."

    try:
        parsed = urlparse(payload)
        if not parsed.scheme:
            payload = "https://" + payload
            parsed  = urlparse(payload)
    except ValueError:
        return False, "Malformed URL — unable to parse."

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http/https are analysed."

    if not parsed.netloc:
        return False, "URL has no host component."

    return True, ""
