"""
routes/admin.py — Admin Dashboard API
=======================================
All endpoints require a valid admin JWT:
  Authorization: Bearer <token>

Endpoints:
  GET  /api/v1/admin/dashboard          — summary stats + pending count
  GET  /api/v1/admin/blocklist/pending  — submissions awaiting review
  POST /api/v1/admin/blocklist/approve  — approve a queued entry (activates it)
  POST /api/v1/admin/blocklist/reject   — reject + delete a queued entry
  GET  /api/v1/admin/blocklist/all      — full blocklist (approved + pending)
  DELETE /api/v1/admin/blocklist/<id>   — hard-delete any entry
  GET  /api/v1/admin/scanlogs           — recent scan audit log

Workflow for reported domains:
  1. User calls POST /api/v1/report  → entry created with is_approved=False
  2. Admin sees it in GET /pending
  3. Admin calls POST /approve  → is_approved=True, domain is now active
      OR  POST /reject          → entry deleted
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify

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
def dashboard():
    """Return KPIs for the admin overview page."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_scans    = ScanLog.query.count()
    scans_today    = ScanLog.query.filter(ScanLog.scanned_at >= today).count()
    danger_scans   = ScanLog.query.filter_by(risk_label="danger").count()
    pending_count  = BlocklistEntry.query.filter_by(is_approved=False).count()
    approved_count = BlocklistEntry.query.filter_by(is_approved=True).count()

    # Scans per day for the last 7 days (simple trend)
    trend = []
    for offset in range(6, -1, -1):
        day_start = today - timedelta(days=offset)
        day_end   = day_start + timedelta(days=1)
        count = ScanLog.query.filter(
            ScanLog.scanned_at >= day_start,
            ScanLog.scanned_at < day_end,
        ).count()
        trend.append({
            "date":  day_start.strftime("%Y-%m-%d"),
            "count": count,
        })

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
def pending_reports():
    """List all user-submitted domains awaiting admin review."""
    entries = BlocklistEntry.query.filter_by(is_approved=False)\
                                  .order_by(BlocklistEntry.added_at.desc())\
                                  .all()
    return jsonify({"pending": [e.to_dict() for e in entries]}), 200


@bp.route("/blocklist/all", methods=["GET"])
@admin_required
def all_blocklist():
    """Full blocklist: both approved and pending entries."""
    entries = BlocklistEntry.query.order_by(BlocklistEntry.added_at.desc()).all()
    return jsonify({"entries": [e.to_dict() for e in entries]}), 200


@bp.route("/blocklist/approve", methods=["POST"])
@admin_required
def approve_entry():
    """
    Approve a pending blocklist entry. Sets is_approved=True, making
    the domain immediately active in all reputation checks.
    """
    body = request.get_json(silent=True) or {}
    entry_id = body.get("id")
    if not entry_id:
        return jsonify({"error": "Missing 'id'"}), 400

    entry = BlocklistEntry.query.get(entry_id)
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
    entry_id = body.get("id")
    if not entry_id:
        return jsonify({"error": "Missing 'id'"}), 400

    entry = BlocklistEntry.query.get(entry_id)
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
    """Hard-delete any blocklist entry (approved or pending)."""
    entry = BlocklistEntry.query.get(entry_id)
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
def scan_logs():
    """
    Return the 100 most recent scan records.
    Supports ?label=danger to filter by risk level.
    """
    label = request.args.get("label")
    q     = ScanLog.query.order_by(ScanLog.scanned_at.desc())
    if label in ("safe", "warning", "danger"):
        q = q.filter_by(risk_label=label)
    rows = q.limit(100).all()

    return jsonify({
        "count": len(rows),
        "logs": [
            {
                "id":           r.id,
                "raw_url":      r.raw_url,
                "resolved_url": r.resolved_url,
                "risk_score":   r.risk_score,
                "risk_label":   r.risk_label,
                "top_threat":   r.top_threat,
                "hop_count":    r.hop_count,
                # client_ip intentionally omitted from list view
                "scanned_at":   r.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for r in rows
        ],
    }), 200
