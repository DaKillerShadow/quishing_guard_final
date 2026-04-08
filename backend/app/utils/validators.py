"""validators.py — Request input validation."""
import re
from urllib.parse import urlparse

# QR payloads that are NOT URLs (skip URL analysis)
# Kept strictly lowercase for case-insensitive matching
_NON_URL_PREFIXES = (
    "wifi:", "begin:vcard", "begin:vcalendar",
    "matmsg:", "tel:", "sms:", "geo:", "mailto:",
    "smsto:", "mms:", "bitcoin:", "ethereum:", "litecoin:",
    "javascript:", "data:", "file:", "blob:", "vbscript:" # Added web exploit schemes
)

# Supported URL schemes
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Max URL length (WHATWG recommends ≤ 2083 for IE compat; we're generous)
MAX_URL_LEN = 8192

# Matches valid RFC 3986 URI schemes (e.g., http:, https:, ftp:)
_SCHEME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:")


def validate_url_payload(payload: str) -> tuple[bool, str]:
    """
    Validate a QR-decoded URL payload before analysis.

    Returns:
        (is_valid: bool, reason: str)  — reason is '' when valid.
    """
    if not payload or not isinstance(payload, str):
        return False, "Payload must be a non-empty string."

    # 1. Strip whitespace and sanitize CRLF (Prevent Log Poisoning)
    payload = payload.strip().replace("\r", "").replace("\n", "")

    if len(payload) > MAX_URL_LEN:
        return False, f"Payload exceeds maximum length of {MAX_URL_LEN} characters."

    # 2. Case-insensitive prefix check to catch non-navigable QR codes
    payload_lower = payload.lower()
    if payload_lower.startswith(_NON_URL_PREFIXES):
        return False, "Non-URL or dangerous QR payload type detected. Analysis not applicable."

    # 3. Handle bare domains with ports safely BEFORE urlparse gets confused
    # If it doesn't start with a valid scheme format, assume it's a bare domain.
    if not _SCHEME_REGEX.match(payload):
        payload = "https://" + payload

    # 4. Strict Parsing
    try:
        parsed = urlparse(payload)
    except ValueError:
        return False, "Malformed URL — unable to parse."

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http/https are analysed."

    if not parsed.netloc:
        return False, "URL has no host component."

    return True, ""
