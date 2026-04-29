"""
routes/health.py — GET /api/v1/health (v2.7.3)
===============================================
Public liveness probe used by monitoring systems and the Flutter app
to verify the backend is reachable.

Fixes applied (Batch 2):
  RTE-05  url_prefix removed from Blueprint() constructor — single source
          of truth is register_blueprint() in __init__.py.
  RTE-07  Sensitive operational stats (danger_scans, pending_reports) 
          removed from the public response. These metrics allowed 
          unauthenticated callers to infer admin queue depth and 
          detection rates — useful intelligence for attackers probing 
          the system. They are now exclusive to /admin/dashboard.
  RTE-08  Four sequential COUNT(*) queries cached with a 10-second TTL.
          At 120 req/min the health endpoint previously fired up to
          480 DB queries/min from monitoring probes alone. Now it fires
          at most 6 per minute (once per 10 s TTL window).
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
from flask import Blueprint, jsonify

from ..limiter          import limiter
from ..models.db_models import ScanLog, BlocklistEntry

# AUDIT FIX [RTE-05]: url_prefix removed from constructor.
bp     = Blueprint("health", __name__)
_START = datetime.now(timezone.utc)

# AUDIT FIX [RTE-08]: Module-level stats cache with 10-second TTL.
# Regenerated at most once per 10 s regardless of probe frequency.
_STATS_TTL     = 10.0  # seconds
_stats_cache:  dict   = {}
_stats_loaded: float  = 0.0


def _get_cached_stats() -> tuple[str, dict]:
    """
    Return (db_status, stats_dict) from the cache, refreshing if stale.
    Isolates all DB calls so the main handler stays clean.
    """
    global _stats_cache, _stats_loaded

    now = time.monotonic()
    if (now - _stats_loaded) < _STATS_TTL and _stats_cache:
        return _stats_cache.get("db_status", "ok"), _stats_cache.get("stats", {})

    try:
        total_scans  = ScanLog.query.count()
        scans_today  = ScanLog.query.filter(
            ScanLog.scanned_at >= datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        ).count()
        db_status = "ok"

        # AUDIT FIX [RTE-07]: danger_scans and pending_reports removed.
        # These operational metrics are only returned on the authenticated
        # /admin/dashboard endpoint to avoid leaking intelligence to scanners.
        stats = {
            "total_scans":  total_scans,
            "scans_today":  scans_today,
        }
    except Exception:
        db_status = "error"
        stats     = {}

    _stats_cache  = {"db_status": db_status, "stats": stats}
    _stats_loaded = now
    return db_status, stats


@bp.route("/health", methods=["GET"])
@limiter.limit("120 per minute")
def health():
    db_status, stats = _get_cached_stats()
    uptime = int((datetime.now(timezone.utc) - _START).total_seconds())

    return jsonify({
        "status":         "ok",
        "service":        "quishing-guard-api",
        "version":        "2.0.0",
        "uptime_seconds": uptime,
        "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "database":       db_status,
        "stats":          stats,
    }), 200
