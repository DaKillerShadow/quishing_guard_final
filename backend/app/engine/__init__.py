"""
engine/__init__.py — Security Engine Interface
==============================================
Exposes the core analytical functions to the rest of the application.
Acting as the central hub for Reputation, Heuristics, and Resolution.
"""

# ── 1. Core Analytical Exports ───────────────────────────────────────────────
from .entropy    import dga_score, EntropyResult
from .reputation import add_to_blocklist, is_allowlisted, is_blocklisted, seed_database
from .resolver   import resolve, ResolverResult
from .scorer import analyse_url

# ── 2. Public API Definition ─────────────────────────────────────────────────
# Alphabetized for clarity and PEP 8 compliance
__all__ = (
    "add_to_blocklist",
    "analyze_url",
    "dga_score",
    "EntropyResult",
    "is_allowlisted",
    "is_blocklisted",
    "resolve",
    "ResolverResult",
    "seed_database",
)
