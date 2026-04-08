"""
reputation.py — Reputation & List Management Engine
===================================================
Handles domain-level trust and threat intelligence using:
1. Built-in seed lists
2. SQLAlchemy Database (Allowlist/Blocklist)
3. Tranco Top 100k CSV (High Reputation Killer)
"""
from __future__ import annotations  # ✅ Line 1: Fixed SyntaxError
import os
import csv
import functools
import tldextract
from sqlalchemy.exc import OperationalError

# ── 1. Path Resolution ────────────────────────────────────────────────────────
# Finds 'backend/app/data/tranco_top_100k.csv'
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "tranco_top_100k.csv")

# ── 2. Built-in Seed Lists (Fallback) ─────────────────────────────────────────

_BUILTIN_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "goo.gl", "microsoft.com", "apple.com", 
    "paypal.com", "github.com", "amazon.com", "cloudflare.com", "whatsapp.com",
    "aou.edu.eg", "coursera.org", "instapay.eg"
})

_BUILTIN_BLOCKLIST: frozenset[str] = frozenset({
    "xn--pple-43d.com", "xn--mcrosoft-n2a.com", "paypa1.com", "arnazon.com"
})

# ── 3. Helper & Loading Functions ─────────────────────────────────────────────

def _get_etld1(url_or_hostname: str) -> str:
    """Standardized domain extraction (e.g., 'sub.google.com' -> 'google.com')."""
    ext = tldextract.extract(url_or_hostname)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower().strip()
    return ext.domain.lower().strip()

@functools.lru_cache(maxsize=1)
def load_tranco_list() -> set[str]:
    """Loads the top 100k domains into memory for O(1) lookups."""
    trusted_domains = set()
    try:
        if not os.path.exists(CSV_PATH):
            print(f"⚠️ WARNING: Reputation list not found at {CSV_PATH}")
            return trusted_domains

        with open(CSV_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    # Row 1 is the domain in Tranco CSV
                    trusted_domains.add(row[1].strip().lower())
        
        print(f"✅ Reputation Engine: Loaded {len(trusted_domains)} trusted domains.")
    except Exception as e:
        print(f"❌ Error loading reputation list: {e}")
    
    return trusted_domains

# ── 4. Public API ─────────────────────────────────────────────────────────────

def is_highly_trusted(url_or_hostname: str) -> bool:
    """Checks if a domain exists in the Tranco Top 100k."""
    domain = _get_etld1(url_or_hostname)
    trusted_set = load_tranco_list()
    return domain in trusted_set

def is_allowlisted(url_or_hostname: str) -> bool:
    """Check if domain is trusted via Built-in list, Tranco, or DB."""
    domain = _get_etld1(url_or_hostname)
    
    if domain in _BUILTIN_ALLOWLIST or is_highly_trusted(domain):
        return True

    try:
        from ..models.db_models import AllowlistEntry
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception:
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    """Check if domain is malicious via Built-in list or DB."""
    domain = _get_etld1(url_or_hostname)
    
    if domain in _BUILTIN_BLOCKLIST:
        return True

    try:
        from ..models.db_models import BlocklistEntry
        # Only block if approved by an admin
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception:
        return False

def add_to_blocklist(domain_raw: str, reason: str = "user_report") -> None:
    """Submit a domain for admin review in the database."""
    domain = _get_etld1(domain_raw)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(domain=domain, reason=reason, is_approved=False)
            db.session.add(entry)
            db.session.commit()
    except Exception:
        pass

# ── 5. Database Seeding ───────────────────────────────────────────────────────

def seed_database() -> None:
    """Populates the database with built-in seeds."""
    try:
        from ..models.db_models import BlocklistEntry, AllowlistEntry
        from ..database import db

        # Logic to only add if not already present
        for domain in _BUILTIN_BLOCKLIST:
            if not BlocklistEntry.query.filter_by(domain=domain).first():
                db.session.add(BlocklistEntry(domain=domain, reason="seed", is_approved=True))
        
        for domain in _BUILTIN_ALLOWLIST:
            if not AllowlistEntry.query.filter_by(domain=domain).first():
                db.session.add(AllowlistEntry(domain=domain))

        db.session.commit()
        print("✅ Database Seeding: Completed.")
    except Exception as e:
        print(f"⚠️ DB Error during seeding: {e}")