"""
reputation.py — Reputation & List Management Engine (v2.7.3)
============================================================
Fixes applied:
  ENG-07  lru_cache replaced with an explicit module-level singleton
          with TTL-based expiry and a manual invalidate function.
          Prevents stale cache after CSV updates and gives operators
          control over memory lifetime.
  ENG-18  add_to_blocklist() now returns bool so callers can surface
          DB write failures to the HTTP client.
"""

from __future__ import annotations
import os
import csv
import time
import threading
import tldextract
from ..logger import get_logger

log = get_logger("reputation")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "tranco_top_100k.csv")

# ── AUDIT FIX [ENG-07]: TTL-based cache replacing lru_cache ──────────────────
# Default TTL: 6 hours. Override with TRANCO_CACHE_TTL_SECONDS env var.
_TRANCO_CACHE_TTL = int(os.environ.get("TRANCO_CACHE_TTL_SECONDS", str(6 * 3600)))

_tranco_set:      set[str]  = set()
_tranco_loaded_at: float    = 0.0
_tranco_lock:     threading.Lock = threading.Lock()


def _is_cache_stale() -> bool:
    return (time.monotonic() - _tranco_loaded_at) > _TRANCO_CACHE_TTL


def invalidate_tranco_cache() -> None:
    """Force the next call to load_tranco_list() to reload from disk."""
    global _tranco_loaded_at
    with _tranco_lock:
        _tranco_loaded_at = 0.0
    log.info("Tranco cache invalidated — will reload on next request.")


def load_tranco_list() -> set[str]:
    """
    Returns the in-memory Tranco domain set, reloading from disk when the
    TTL has elapsed or on first call.
    """
    global _tranco_set, _tranco_loaded_at

    # Fast path — no lock needed for a stale check read
    if not _is_cache_stale():
        return _tranco_set

    with _tranco_lock:
        # Double-checked locking: another thread may have reloaded while we waited
        if not _is_cache_stale():
            return _tranco_set

        trusted_domains: set[str] = set()
        try:
            if not os.path.exists(CSV_PATH):
                log.warning("Reputation list (Tranco) not found at %s", CSV_PATH)
                return _tranco_set  # Return stale rather than empty on missing file

            with open(CSV_PATH, mode="r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        trusted_domains.add(row[1].strip().lower())

            _tranco_set       = trusted_domains
            _tranco_loaded_at = time.monotonic()
            log.info("Tranco reloaded: %d domains cached.", len(_tranco_set))

        except Exception as e:
            log.error("Failed to reload Tranco list: %s", e)
            # Keep serving the stale set rather than returning empty

    return _tranco_set


# ── Built-in Seed Lists ───────────────────────────────────────────────────────

_BUILTIN_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "goo.gl", "microsoft.com", "apple.com",
    "paypal.com", "github.com", "amazon.com", "cloudflare.com", "whatsapp.com",
    "aou.edu.eg", "coursera.org", "instapay.eg", "linktr.ee"
})

_BUILTIN_BLOCKLIST: frozenset[str] = frozenset({
    "xn--pple-43d.com", "xn--mcrosoft-n2a.com", "paypa1.com", "arnazon.com"
})


# ── Internal Logic ─────────────────────────────────────────────────────────────

def _get_etld1(url_or_hostname: str) -> str:
    if not url_or_hostname:
        return ""
    ext = tldextract.extract(url_or_hostname.lower().strip())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or url_or_hostname.lower().strip()


# ── Public API ─────────────────────────────────────────────────────────────────

def is_highly_trusted(url_or_hostname: str) -> bool:
    domain = _get_etld1(url_or_hostname)
    return domain in load_tranco_list()

def is_allowlisted(url_or_hostname: str) -> bool:
    domain = _get_etld1(url_or_hostname)
    if domain in _BUILTIN_ALLOWLIST or is_highly_trusted(domain):
        return True
    try:
        from ..models.db_models import AllowlistEntry
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception:
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    domain = _get_etld1(url_or_hostname)
    if domain in _BUILTIN_BLOCKLIST:
        return True
    try:
        from ..models.db_models import BlocklistEntry
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception:
        return False

def add_to_blocklist(domain_raw: str, reason: str = "user_report") -> bool:
    """
    Submits a domain for admin review.
    AUDIT FIX [ENG-18]: Returns True on success, False on failure.
    """
    domain = _get_etld1(domain_raw)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(domain=domain, reason=reason, is_approved=False)
            db.session.add(entry)
            db.session.commit()
            log.info("Domain %s submitted for blocklist review.", domain)
        return True
    except Exception as e:
        log.error("Failed to submit report for %s: %s", domain, e)
        return False  # AUDIT FIX [ENG-18]


# ── Database Seeding ───────────────────────────────────────────────────────────

def seed_database() -> None:
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
