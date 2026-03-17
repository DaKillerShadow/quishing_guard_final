"""
engine/__init__.py — Logic Layer Exports
========================================
Exposes core security engines to the rest of the application.
"""

from .scorer     import analyze_url
from .resolver   import resolve
from .reputation import is_allowlisted, is_blocklisted, seed_database

# This ensures that when you do 'from ..engine.scorer import analyze_url', it works.