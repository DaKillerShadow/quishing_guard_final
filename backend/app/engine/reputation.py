"""
reputation.py — Reputation & List Management Engine (v2.7.2)
============================================================
Handles domain-level trust and threat intelligence using a 
tri-tier validation strategy:
  1. Built-in high-confidence seed lists.
  2. SQLAlchemy Database (Dynamic Admin Allow/Block).
  3. Tranco Top 100k (Global high-traffic immunity).
"""

from __future__ import annotations
import os
import csv
import functools
import tldextract
from ..logger import get_logger

log = get_logger("reputation")

# ── 1. Path Resolution ────────────────────────────────────────────────────────
# Locates the Tranco CSV at 'backend/app/data/tranco_top_100k.csv'
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "tranco_top_100k.csv")

# ── 2. Built-in Seed Lists (Instant Fallback) ─────────────────────────────────

_BUILTIN_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "goo.gl", "microsoft.com", "apple.com", 
    "paypal.com", "github.com", "amazon.com", "cloudflare.com", "whatsapp.com",
    "aou.edu.eg", "coursera.org", "instapay.eg", "linktr.ee"
})

_BUILTIN_BLOCKLIST: frozenset[str] = frozenset({
    "xn--pple-43d.com", "xn--mcrosoft-n2a.com", "paypa1.com", "arnazon.com"
})

# ── 3. Internal Logic ─────────────────────────────────────────────────────────

def _get_etld1(url_or_hostname: str) -> str:
    """
    Extracts the Effective Top-Level Domain + 1 (ETLD+1).
    Example: 'sub.google.com' -> 'google.com'
    """
    if not url_or_hostname:
        return ""
    ext = tldextract.extract(url_or_hostname.lower().strip())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or url_or_hostname.lower().strip()

@functools.lru_cache(maxsize=1)
def load_tranco_list() -> set[str]:
    """
    Loads the Tranco list into an in-memory set for O(1) lookups.
    Cached indefinitely after the first call to maximize performance.
    """
    trusted_domains = set()
    try:
        if not os.path.exists(CSV_PATH):
            log.warning("Reputation list (Tranco) not found at %s", CSV_PATH)
            return trusted_domains

        with open(CSV_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    # In Tranco CSV: Column 0 is Rank, Column 1 is Domain
                    trusted_domains.add(row[1].strip().lower())
        
        log.info("Reputation Engine: Successfully loaded %d trusted domains.", len(trusted_domains))
    except Exception as e:
        log.error("Failed to load reputation list: %s", e)
    
    return trusted_domains

# ── 4. Public API ─────────────────────────────────────────────────────────────

def is_highly_trusted(url_or_hostname: str) -> bool:
    """Checks if a domain exists in the Tranco Top 100k Global List."""
    domain = _get_etld1(url_or_hostname)
    return domain in load_tranco_list()

def is_allowlisted(url_or_hostname: str) -> bool:
    """
    Multi-tier trust check. A domain is 'Safe' if found in:
    Built-in Seeds OR Tranco List OR Database Allowlist.
    """
    domain = _get_etld1(url_or_hostname)
    
    # Tier 1: Static Seeds & Tranco
    if domain in _BUILTIN_ALLOWLIST or is_highly_trusted(domain):
        return True

    # Tier 2: Dynamic Database
    try:
        from ..models.db_models import AllowlistEntry
        # Perform check via local DB
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception:
        # If DB is down, we fall back to static tiers silently
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    """
    Checks if domain is confirmed malicious via:
    Built-in Seeds OR Database Blocklist (must be admin-approved).
    """
    domain = _get_etld1(url_or_hostname)
    
    if domain in _BUILTIN_BLOCKLIST:
        return True

    try:
        from ..models.db_models import BlocklistEntry
        # Only domains flagged and APPROVED by admin are blocked here
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception:
        return False

def add_to_blocklist(domain_raw: str, reason: str = "user_report") -> None:
    """Submits a domain to the database for future admin approval."""
    domain = _get_etld1(domain_raw)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        # Prevent duplicate reports
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(domain=domain, reason=reason, is_approved=False)
            db.session.add(entry)
            db.session.commit()
            log.info("Domain %s submitted for blocklist review.", domain)
    except Exception as e:
        log.error("Failed to submit report for %s: %s", domain, e)

# ── 5. Database Seeding ───────────────────────────────────────────────────────

def seed_database() -> None:
    """Syncs built-in block/allow seeds to the DB on first deployment."""
    try:
        from ..models.db_models import BlocklistEntry, AllowlistEntry
        from ..database import db

        for domain in _BUILTIN_BLOCKLIST:
            if not BlocklistEntry.query.filter_by(domain=domain).first():
                db.session.add(BlocklistEntry(domain=domain, reason="seed", is_approved=True))
        
        for domain in _BUILTIN_ALLOWLIST:
            if not AllowlistEntry.query.filter_by(domain=domain).first():
                db.session.add(AllowlistEntry(domain=domain))

        db.session.commit()
        log.info("Database Seeding: Synchronization completed.")
    except Exception as e:
        log.error("Database Seeding Error: %s", e)
