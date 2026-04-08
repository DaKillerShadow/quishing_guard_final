"""
routes/health.py — GET /api/v1/health
=======================================
Returns real-time stats from the database instead of static values.
Rate limited to 120 requests/minute (allows monitoring probes).
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify

from ..limiter          import limiter
from ..models.db_models import ScanLog, BlocklistEntry

bp     = Blueprint("health", __name__, url_prefix="/api/v1")
_START = datetime.now(timezone.utc)


@bp.route("/health", methods=["GET"])
@limiter.limit("120 per minute")
def health():
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        total_scans  = ScanLog.query.count()
        scans_today  = ScanLog.query.filter(ScanLog.scanned_at >= today).count()
        danger_count = ScanLog.query.filter_by(risk_label="danger").count()
        pending      = BlocklistEntry.query.filter_by(is_approved=False).count()
        db_status    = "ok"
    except Exception:
        total_scans = scans_today = danger_count = pending = None
        db_status   = "error"

    uptime = int((datetime.now(timezone.utc) - _START).total_seconds())

    return jsonify({
        "status":         "ok",
        "service":        "quishing-guard-api",
        "version":        "2.0.0",
        "uptime_seconds": uptime,
        "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "database":       db_status,
        "stats": {
            "total_scans":       total_scans,
            "scans_today":       scans_today,
            "danger_scans":      danger_count,
            "pending_reports":   pending,
        },
    }), 200
