"""
engine/__init__.py — Engine Module Exports
==========================================
Exposes the core security functions to the rest of the application.
"""

from .entropy    import dga_score, EntropyResult
from .reputation import is_allowlisted, is_blocklisted, seed_database, add_to_blocklist
from .resolver   import resolve, ResolverResult
from .scorer     import analyze_url

# We keep __all__ clean to avoid "cannot import name" errors on Render
__all__ = (
    "EntropyResult",
    "ResolverResult",
    "add_to_blocklist",
    "analyze_url",
    "dga_score",
    "is_allowlisted",
    "is_blocklisted",
    "resolve",
    "seed_database",
)
