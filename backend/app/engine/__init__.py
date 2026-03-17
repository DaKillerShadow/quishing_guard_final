"""
engine/__init__.py — Engine Module Exports
==========================================
Exposes the core security functions to the rest of the application.
Ensures clean imports like: from engine import resolve, score
"""

from .entropy    import dga_score, EntropyResult
from .resolver   import resolve, ResolverResult  # Moved ResolverResult here
from .reputation import is_allowlisted, is_blocklisted, seed_database
from .scorer import analyze_url
from .reputation import add_to_blocklist # Assuming this is in reputation.py

__all__ = [
    "dga_score", 
    "EntropyResult",
    "resolve", 
    "ResolverResult",
    "score", 
    "ScorerResult", 
    "CheckResult",
    "is_allowlisted", 
    "is_blocklisted", 
    "add_to_blocklist",
    "seed_database"
]