from __future__ import annotations
import tldextract
from flask import current_app

# ── Built-in seed lists ───────────────────────────────────────────────────────
_BUILTIN_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "goo.gl",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", 
    "twitter.com", "x.com", "linkedin.com", "youtube.com", "tiktok.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "github.com", "gitlab.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "wise.com", "revolut.com",
    "zoom.us", "slack.com", "discord.com", "whatsapp.com",
    "aou.edu.eg", "coursera.org", "edx.org",
})

_BUILTIN_BLOCKLIST: frozenset[str] = frozenset({
    "xn--pple-43d.com",    # punycode apple spoof
    "xn--mcrosoft-n2a.com",# punycode microsoft spoof
    "paypa1.com",           # typosquat
    "arnazon.com",          # typosquat
})

# ── Extraction Helper ─────────────────────────────────────────────────────────

def _get_etld1(url_or_hostname: str) -> str:
    """Standardized domain extraction using tldextract."""
    ext = tldextract.extract(url_or_hostname)
    return f"{ext.domain}.{ext.suffix}".lower().strip()

# ── Public API ────────────────────────────────────────────────────────────────

def is_allowlisted(url_or_hostname: str) -> bool:
    domain = _get_etld1(url_or_hostname)
    # Check built-in list
    if domain in _BUILTIN_ALLOWLIST:
        return True
    # Check DB
    try:
        from ..models.db_models import AllowlistEntry
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception:
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    domain = _get_etld1(url_or_hostname)
    # Check built-in list
    if domain in _BUILTIN_BLOCKLIST:
        return True
    # Check DB
    try:
        from ..models.db_models import BlocklistEntry
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception:
        return False

def add_to_blocklist(domain: str, reason: str = "user_report") -> None:
    domain = _get_etld1(domain)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(domain=domain, reason=reason, is_approved=False)
            db.session.add(entry)
            db.session.commit()
    except Exception:
        pass

# ── [THE MISSING FUNCTION] ────────────────────────────────────────────────────

def seed_database() -> None:
    """
    Populates the database with built-in seeds if they don't exist.
    """
    from ..models.db_models import BlocklistEntry, AllowlistEntry
    from ..database import db

    # Seed Blocklist
    for domain in _BUILTIN_BLOCKLIST:
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            db.session.add(BlocklistEntry(
                domain=domain, reason="seed", added_by="seed", is_approved=True
            ))

    # Seed Allowlist
    for domain in _BUILTIN_ALLOWLIST:
        if not AllowlistEntry.query.filter_by(domain=domain).first():
            db.session.add(AllowlistEntry(domain=domain))

    db.session.commit()