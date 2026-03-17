"""
engine/__init__.py — Engine Module Exports
==========================================
Exposes the core security functions to the rest of the application.
"""

from .resolver   import resolve, ResolverResult
from .reputation import is_allowlisted, is_blocklisted, seed_database, add_to_blocklist
from .scorer     import analyze_url

# We keep __all__ clean to avoid "cannot import name" errors on Render
__all__ = [
    "resolve", 
    "ResolverResult",
    "analyze_url", 
    "is_allowlisted", 
    "is_blocklisted", 
    "add_to_blocklist",
    "seed_database"
]