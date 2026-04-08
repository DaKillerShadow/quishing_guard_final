"""
routes/health.py — GET /api/v1/health
=======================================
Returns real-time stats from the database instead of static values.
Rate limited to 120 requests/minute (allows monitoring probes).
Utilizes an in-memory cache to prevent PostgreSQL COUNT() bottlenecks.
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify

from ..limiter          import limiter
from ..models.db_models import ScanLog, BlocklistEntry

bp     = Blueprint("health", __name__, url_prefix="/api/v1")
_START = datetime.now(timezone.utc)

# ── Lightweight In-Memory Cache for Heavy DB Stats ──
_stats_cache = {
    "timestamp": None,
    "data": {
        "total_scans": None,
        "scans_today": None,
        "danger_scans": None,
        "pending_reports": None,
    },
    "db_status": "ok"
}

def _get_cached_stats():
    """Fetches stats from DB maximum once per 60 seconds to prevent DB overload."""
    now = datetime.now(timezone.utc)
    
    # If cache is less than 60 seconds old, return the cached data
    if _stats_cache["timestamp"] and (now - _stats_cache["timestamp"]).total_seconds() < 60:
        return _stats_cache["data"], _stats_cache["db_status"]

    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        data = {
            "total_scans":       ScanLog.query.count(),
            "scans_today":       ScanLog.query.filter(ScanLog.scanned_at >= today).count(),
            "danger_scans":      ScanLog.query.filter_by(risk_label="danger").count(),
            "pending_reports":   BlocklistEntry.query.filter_by(is_approved=False).count(),
        }
        db_status = "ok"
    except Exception:
        data = {
            "total_scans": None, "scans_today": None, 
            "danger_scans": None, "pending_reports": None
        }
        db_status = "error"

    # Update the cache
    _stats_cache["timestamp"] = now
    _stats_cache["data"] = data
    _stats_cache["db_status"] = db_status

    return data, db_status


@bp.route("/health", methods=["GET"])
@limiter.limit("120 per minute")
def health():
    uptime = int((datetime.now(timezone.utc) - _START).total_seconds())
    
    # Fetch from our new caching function
    stats_data, db_status = _get_cached_stats()

    return jsonify({
        "status":         "ok",
        "service":        "quishing-guard-api",
        "version":        "2.0.0",
        "uptime_seconds": uptime,
        "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "database":       db_status,
        "stats":          stats_data,
    }), 200
