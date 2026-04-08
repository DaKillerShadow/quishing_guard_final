"""
routes/admin.py — Admin Dashboard API
=======================================
All endpoints require a valid admin JWT:
  Authorization: Bearer <token>
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from sqlalchemy import func 

from ..database          import db
from ..models.db_models  import BlocklistEntry, ScanLog
from ..utils.auth        import admin_required
from ..limiter           import limiter
from ..logger            import get_logger

bp  = Blueprint("admin", __name__, url_prefix="/api/v1/admin")
log = get_logger("admin")


# ── Dashboard summary ─────────────────────────────────────────────────────────

@bp.route("/dashboard", methods=["GET"])
@admin_required
@limiter.limit("60 per minute") # Guard against compromised token DoS
def dashboard():
    """Return KPIs for the admin overview page with PostgreSQL-optimized querying."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = today_start - timedelta(days=7)

    total_scans    = ScanLog.query.count()
    scans_today    = ScanLog.query.filter(ScanLog.scanned_at >= today_start).count()
    danger_scans   = ScanLog.query.filter_by(risk_label="danger").count()
    pending_count  = BlocklistEntry.query.filter_by(is_approved=False).count()
    approved_count = BlocklistEntry.query.filter_by(is_approved=True).count()

    # PostgreSQL-safe date extraction using CAST
    trend_data = db.session.query(
        func.cast(ScanLog.scanned_at, db.Date).label("day"),
        func.count(ScanLog.id).label("count")
    ).filter(ScanLog.scanned_at >= seven_days_ago)\
     .group_by("day")\
     .order_by("day")\
     .all()

    trend = [{"date": str(row.day), "count": row.count} for row in trend_data]

    return jsonify({
        "total_scans":    total_scans,
        "scans_today":    scans_today,
        "danger_scans":   danger_scans,
        "pending_reports": pending_count,
        "approved_blocked": approved_count,
        "scan_trend_7d":  trend,
    }), 200


# ── Blocklist management ──────────────────────────────────────────────────────

@bp.route("/blocklist/pending", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def pending_reports():
    """List all user-submitted domains awaiting admin review (Paginated)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    
    pagination = BlocklistEntry.query.filter_by(is_approved=False)\
                                     .order_by(BlocklistEntry.added_at.desc())\
                                     .paginate(page=page, per_page=per_page, error_out=False)
                                     
    return jsonify({
        "pending": [e.to_dict() for e in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    }), 200


@bp.route("/blocklist/all", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def all_blocklist():
    """Full blocklist: both approved and pending entries (Paginated to prevent OOM)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    
    pagination = BlocklistEntry.query.order_by(BlocklistEntry.added_at.desc())\
                                     .paginate(page=page, per_page=per_page, error_out=False)
                                     
    return jsonify({
        "entries": [e.to_dict() for e in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    }), 200


@bp.route("/blocklist/approve", methods=["POST"])
@admin_required
def approve_entry():
    """Approve a pending blocklist entry."""
    body = request.get_json(silent=True) or {}
    try:
        entry_id = int(body.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Missing or invalid 'id'"}), 400

    entry = db.session.get(BlocklistEntry, entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404

    entry.is_approved = True
    entry.added_by    = "admin"
    db.session.commit()

    log.info("Blocklist entry approved",
             extra={"domain": entry.domain, "id": entry.id})
    return jsonify({"status": "approved", "domain": entry.domain}), 200


@bp.route("/blocklist/reject", methods=["POST"])
@admin_required
def reject_entry():
    """Delete a pending entry without activating it."""
    body = request.get_json(silent=True) or {}
    try:
        entry_id = int(body.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Missing or invalid 'id'"}), 400

    entry = db.session.get(BlocklistEntry, entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404

    domain = entry.domain
    db.session.delete(entry)
    db.session.commit()

    log.info("Blocklist entry rejected",
             extra={"domain": domain, "id": entry_id})
    return jsonify({"status": "rejected", "domain": domain}), 200


@bp.route("/blocklist/<int:entry_id>", methods=["DELETE"])
@admin_required
def delete_entry(entry_id: int):
    """Hard-delete any blocklist entry."""
    entry = db.session.get(BlocklistEntry, entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404

    domain = entry.domain
    db.session.delete(entry)
    db.session.commit()

    log.info("Blocklist entry deleted", extra={"domain": domain, "id": entry_id})
    return jsonify({"status": "deleted", "domain": domain}), 200


# ── Scan audit log ────────────────────────────────────────────────────────────

@bp.route("/scanlogs", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def scan_logs():
    """
    Return the scan records (Paginated).
    Uses the Model's to_dict() method for cleaner code.
    """
    label = request.args.get("label")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    
    q = ScanLog.query.order_by(ScanLog.scanned_at.desc())
    
    if label in ("safe", "warning", "danger"):
        q = q.filter_by(risk_label=label)
        
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "logs": [r.to_dict() for r in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    }), 200

