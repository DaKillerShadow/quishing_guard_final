"""
reputation.py — Reputation & List Management Engine
===================================================
Handles domain-level trust and threat intelligence. 
Replaces flat JSON files with SQLAlchemy-backed lookups.
"""

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
    # 👈 Fixed: Prevents trailing dots for IPs or domains without suffixes
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower().strip()
    return ext.domain.lower().strip()

# ── Public API ────────────────────────────────────────────────────────────────

def is_allowlisted(url_or_hostname: str) -> bool:
    """Check if a domain is trusted via built-in list or DB."""
    domain = _get_etld1(url_or_hostname)
    # Check built-in list
    if domain in _BUILTIN_ALLOWLIST:
        return True
    # Check DB
    try:
        from ..models.db_models import AllowlistEntry
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception as e:
        current_app.logger.error(f"DB Error checking allowlist for {domain}: {e}")
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    """Check if a domain is malicious via built-in list or DB."""
    domain = _get_etld1(url_or_hostname)
    # Check built-in list
    if domain in _BUILTIN_BLOCKLIST:
        return True
    # Check DB
    try:
        from ..models.db_models import BlocklistEntry
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception as e:
        current_app.logger.error(f"DB Error checking blocklist for {domain}: {e}")
        return False

def add_to_blocklist(domain: str, reason: str = "user_report") -> None:
    """Submit a domain for admin review."""
    domain = _get_etld1(domain)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(domain=domain, reason=reason, is_approved=False)
            db.session.add(entry)
            db.session.commit()
    except Exception as e:
        current_app.logger.error(f"DB Error adding to blocklist for {domain}: {e}")

# ── [THE MISSING FUNCTION] ────────────────────────────────────────────────────

def seed_database() -> None:
    """
    Populates the database with built-in seeds if they don't exist.
    Optimized to use bulk lookups instead of querying in a loop to prevent N+1 query bottlenecks.
    """
    from ..models.db_models import BlocklistEntry, AllowlistEntry
    from ..database import db

    try:
        # 1. Fetch all existing domains from the DB into memory using entities only for speed
        existing_blocks = {entry.domain for entry in BlocklistEntry.query.with_entities(BlocklistEntry.domain).all()}
        existing_allows = {entry.domain for entry in AllowlistEntry.query.with_entities(AllowlistEntry.domain).all()}

        # 2. Find what is missing using sets
        missing_blocks = _BUILTIN_BLOCKLIST - existing_blocks
        missing_allows = _BUILTIN_ALLOWLIST - existing_allows

        # 3. Add only the missing entries
        for domain in missing_blocks:
            db.session.add(BlocklistEntry(
                domain=domain, 
                reason="seed", 
                added_by="seed", 
                is_approved=True
            ))
            
        for domain in missing_allows:
            db.session.add(AllowlistEntry(domain=domain))

        # 4. Commit once for the whole transaction
        if missing_blocks or missing_allows:
            db.session.commit()
    except Exception as e:
        # Fallback to standard logging if current_app isn't ready during boot
        print(f"DB Error seeding database: {e}")
            db.session.commit()
    except Exception as e:
        current_app.logger.error(f"DB Error seeding database: {e}")
