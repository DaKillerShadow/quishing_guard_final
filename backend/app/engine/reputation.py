"""
reputation.py — Integrated Reputation & Trust Engine (v2.1.1)
===========================================================
Handles multi-tier domain trust verification. 
Combines high-performance Tranco Top 1M lookups with 
dynamic SQLAlchemy-backed community lists.
"""

from __future__ import annotations
import csv
import os
import tldextract
from flask import current_app

# ── 1. Global Memory Stores ───────────────────────────────────────────────────

# High-performance set for O(1) lookups of the Tranco list
_TRUSTED_DOMAINS: set[str] = set()

_BUILTIN_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "goo.gl",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", 
    "twitter.com", "x.com", "linkedin.com", "tiktok.com",
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

# ── 2. Data Loading (Tranco Tier) ─────────────────────────────────────────────

def load_reputation_data():
    """
    Loads the Tranco list into memory on startup.
    Uses absolute path resolution to find data in the project root.
    """
    global _TRUSTED_DOMAINS
    
    # Get the directory where this file resides (backend/app/engine/)
    base_dir = os.path.dirname(os.path.abspath(__file__)) 
    
    # Step up twice to 'backend/' then into 'data/'
    data_path = os.path.abspath(os.path.join(base_dir, '..', '..', 'data', 'tranco_top_100k.csv'))
    
    try:
        if not os.path.exists(data_path):
            # Log exact path to help debugging if it fails again
            current_app.logger.warning(f"⚠️ Reputation file missing at {data_path}. Skipping Tranco load.")
            return

        with open(data_path, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                # Format: Rank, Domain
                if len(row) >= 2:
                    _TRUSTED_DOMAINS.add(row[1].lower().strip())
        
        current_app.logger.info(f"✅ Reputation Engine: Loaded {len(_TRUSTED_DOMAINS)} domains into Trust Tier.")
    except Exception as e:
        current_app.logger.error(f"❌ Failed to load reputation list: {e}")

# ── 3. Extraction & Normalization ─────────────────────────────────────────────

def _get_etld1(url_or_hostname: str) -> str:
    """Standardized domain extraction using tldextract."""
    ext = tldextract.extract(url_or_hostname)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower().strip()
    return ext.domain.lower().strip()

# ── 4. Public API (Trust & Threat Checks) ─────────────────────────────────────

def is_highly_trusted(url_or_hostname: str) -> bool:
    """Checks if a domain has high global reputation via Tranco."""
    domain = _get_etld1(url_or_hostname)
    return domain in _TRUSTED_DOMAINS

def is_allowlisted(url_or_hostname: str) -> bool:
    """Multi-tier trust check: Tranco -> Built-in -> Database."""
    domain = _get_etld1(url_or_hostname)
    
    if domain in _TRUSTED_DOMAINS or domain in _BUILTIN_ALLOWLIST:
        return True
    
    try:
        from ..models.db_models import AllowlistEntry
        return AllowlistEntry.query.filter_by(domain=domain).first() is not None
    except Exception as e:
        current_app.logger.error(f"DB Error checking allowlist for {domain}: {e}")
        return False

def is_blocklisted(url_or_hostname: str) -> bool:
    """Check if a domain is malicious via built-in list or DB."""
    domain = _get_etld1(url_or_hostname)
    
    if domain in _BUILTIN_BLOCKLIST:
        return True
        
    try:
        from ..models.db_models import BlocklistEntry
        return BlocklistEntry.query.filter_by(domain=domain, is_approved=True).first() is not None
    except Exception as e:
        current_app.logger.error(f"DB Error checking blocklist for {domain}: {e}")
        return False

# ── 5. List Management ────────────────────────────────────────────────────────

def add_to_blocklist(domain: str, reason: str = "user_report", reporter_ip: str | None = None) -> None:
    """Submit a domain for admin review, tracking the reporter's IP."""
    domain = _get_etld1(domain)
    try:
        from ..models.db_models import BlocklistEntry
        from ..database import db
        
        if not BlocklistEntry.query.filter_by(domain=domain).first():
            entry = BlocklistEntry(
                domain=domain, 
                reason=reason, 
                is_approved=False,
                reporter_ip=reporter_ip
            )
            db.session.add(entry)
            db.session.commit()
    except Exception as e:
        current_app.logger.error(f"DB Error adding to blocklist for {domain}: {e}")

# ── 6. Seeding Logic ──────────────────────────────────────────────────────────

def seed_database() -> None:
    """Populates the DB with built-in seeds if they don't exist."""
    from ..models.db_models import BlocklistEntry, AllowlistEntry
    from ..database import db

    try:
        existing_blocks = {e.domain for e in BlocklistEntry.query.with_entities(BlocklistEntry.domain).all()}
        existing_allows = {e.domain for e in AllowlistEntry.query.with_entities(AllowlistEntry.domain).all()}

        missing_blocks = _BUILTIN_BLOCKLIST - existing_blocks
        missing_allows = _BUILTIN_ALLOWLIST - existing_allows

        for domain in missing_blocks:
            db.session.add(BlocklistEntry(
                domain=domain, 
                reason="seed", 
                added_by="seed", 
                reporter_ip="127.0.0.1",
                is_approved=True
            ))
            
        for domain in missing_allows:
            db.session.add(AllowlistEntry(domain=domain))

        if missing_blocks or missing_allows:
            db.session.commit()
            
    except Exception as e:
        print(f"DB Error seeding database: {e}")
