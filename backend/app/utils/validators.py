"""
validators.py — Request input validation (v2.7.1)

Fixes applied:
  ENG-17  MAX_URL_LEN reduced from 8192 to 4296 to match the ISO 18004
          QR code standard maximum for alphanumeric payloads. Accepting
          8192 bytes allowed payloads that could never originate from a
          real QR code, widening the fuzzing surface against the parser.
"""
import re
from urllib.parse import urlparse

_NON_URL_PREFIXES = (
    "wifi:", "begin:vcard", "begin:vcalendar",
    "matmsg:", "tel:", "sms:", "geo:", "mailto:",
    "smsto:", "mms:", "bitcoin:", "ethereum:", "litecoin:",
)

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# AUDIT FIX [ENG-17]: ISO 18004 limits alphanumeric QR payloads to 4,296
# characters. Accepting 8,192 bytes permitted non-QR-origin payloads to
# reach the downstream URL parser, unnecessarily widening the attack surface.
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
