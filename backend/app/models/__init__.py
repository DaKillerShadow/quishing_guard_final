"""
app/models/__init__.py — Models Package Interface
=================================================
Exposes database models at the package level for cleaner imports.
"""

from .db_models import AllowlistEntry, BlocklistEntry, ScanLog

__all__ = [
    "AllowlistEntry",
    "BlocklistEntry",
    "ScanLog",
]
