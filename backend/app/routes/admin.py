"""
routes/admin.py — Admin Dashboard API (v2.7.3)
===============================================
All endpoints require a valid admin JWT:
  Authorization: Bearer <token>

Fixes applied (Batch 2):
  RTE-10  Rate limits added to all mutating endpoints (approve, reject, delete).
          A compromised token could previously automate bulk blocklist changes
          without any throttle. 30/min per IP for mutations; 60/min for reads.
  RTE-16  dashboard() trend query uses SQLAlchemy expression objects instead of
          raw string "day" in group_by/order_by — prevents PostgreSQL portability
          failures where string label resolution differs from SQLite.
  M-5     url_prefix removed from the Blueprint() constructor.
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

# FIX M-5: Removed url_prefix from the Blueprint() constructor.
bp  = Blueprint("admin", __name__)
log = get_logger("admin")


# ── Dashboard summary ─────────────────────────────────────────────────────────

@bp.route("/dashboard", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def dashboard():
    """Return KPIs for the admin overview page with optimized trend querying."""
    now            = datetime.now(timezone.utc)
    today_start    = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = today_start - timedelta(days=7)

    # 1. Global KPIs
    total_scans    = ScanLog.query.count()
    scans_today    = ScanLog.query.filter(ScanLog.scanned_at >= today_start).count()
    danger_scans   = ScanLog.query.filter_by(risk_label="danger").count()
    pending_count  = BlocklistEntry.query.filter_by(is_approved=False).count()
    approved_count = BlocklistEntry.query.filter_by(is_approved=True).count()

    # 2. Optimized Trend: Fetches all 7 days in ONE database round-trip
    # AUDIT FIX [RTE-16]: Use SQLAlchemy expression objects — not raw string
    # labels — in group_by/order_by to ensure correct PostgreSQL behaviour.
    day_expr   = func.date(ScanLog.scanned_at)
    trend_data = (
        db.session.query(day_expr.label("day"), func.count(ScanLog.id).label("count"))
        .filter(ScanLog.scanned_at >= seven_days_ago)
        .group_by(day_expr)          # RTE-16: expression, not string "day"
        .order_by(day_expr)          # RTE-16: expression, not string "day"
        .all()
    )
    trend = [{"date": str(row.day), "count": row.count} for row in trend_data]

    return jsonify({
        "total_scans":      total_scans,
        "scans_today":      scans_today,
        "danger_scans":     danger_scans,
        "pending_reports":  pending_count,
        "approved_blocked": approved_count,
        "scan_trend_7d":    trend,
    }), 200


# ── Blocklist management ──────────────────────────────────────────────────────

@bp.route("/blocklist/pending", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def pending_reports():
    """List all user-submitted domains awaiting admin review."""
    entries = (
        BlocklistEntry.query
        .filter_by(is_approved=False)
        .order_by(BlocklistEntry.added_at.desc())
        .all()
    )
    return jsonify({"pending": [e.to_dict() for e in entries]}), 200


@bp.route("/blocklist/all", methods=["GET"])
@admin_required
@limiter.limit("60 per minute")
def all_blocklist():
    """Full blocklist: both approved and pending entries."""
    entries = BlocklistEntry.query.order_by(BlocklistEntry.added_at.desc()).all()
    return jsonify({"entries": [e.to_dict() for e in entries]}), 200


@bp.route("/blocklist/approve", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")   # AUDIT FIX [RTE-10]: rate-limit mutating endpoint
def approve_entry():
    """Approve a pending blocklist entry."""
    body = request.get_json(silent=True) or {}
    try:
        # Cast to int to prevent type errors during lookup
        entry_id = int(body.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Missing or invalid 'id'"}), 400

    entry = db.session.get(BlocklistEntry, entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404

    entry.is_approved = True
    entry.added_by    = "admin"
    db.session.commit()

    log.info("Blocklist entry approved", extra={"domain": entry.domain, "id": entry.id})
    return jsonify({"status": "approved", "domain": entry.domain}), 200


@bp.route("/blocklist/reject", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")   # AUDIT FIX [RTE-10]
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

    log.info("Blocklist entry rejected", extra={"domain": domain, "id": entry_id})
    return jsonify({"status": "rejected", "domain": domain}), 200


@bp.route("/blocklist/<int:entry_id>", methods=["DELETE"])
@admin_required
@limiter.limit("30 per minute")   # AUDIT FIX [RTE-10]
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
    Return the 100 most recent scan records.
    Uses the Model's to_dict() method for cleaner code.
    """
    label = request.args.get("label")
    q     = ScanLog.query.order_by(ScanLog.scanned_at.desc())

    if label in ("safe", "warning", "danger"):
        q = q.filter_by(risk_label=label)

    rows = q.limit(100).all()
    return jsonify({
        "count": len(rows),
        "logs":  [r.to_dict() for r in rows],
    }), 200
