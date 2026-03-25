"""
routes/report.py — POST /api/v1/report
========================================
User-facing endpoint. Queues a domain for admin review.

SECURITY CHANGE from v1:
  Submissions are stored with is_approved=False and only become active
  after an admin approves them via the dashboard. Users can no longer
  instantly affect the live blocklist.

Rate limit: 10 per minute per IP.
"""
from __future__ import annotations
from flask import Blueprint, request, jsonify

from ..engine.reputation import add_to_blocklist, _get_etld1
from ..utils.validators  import validate_url_payload
from ..limiter           import limiter, get_real_client_ip # Use our proxy-safe IP helper
from ..logger            import get_logger

bp  = Blueprint("report", __name__, url_prefix="/api/v1")
log = get_logger("report")


@bp.route("/report", methods=["POST"])
@limiter.limit("10 per minute")
def report():
    body   = request.get_json(silent=True) or {}
    url    = (body.get("url") or "").strip()
    reason = (body.get("reason") or "user_report").strip()[:200]

    if not url:
        return jsonify({"error": "Missing required field: 'url'"}), 400

    # 1. Validate the payload (ensure it's a URL and not a WIFI/SMS string)
    ok, msg = validate_url_payload(url)
    if not ok:
        return jsonify({"error": msg}), 422

    # 2. Standardize the domain/host extraction
    # We use our engine's helper to ensure the report matches our detection logic
    host = _get_etld1(url)
    if not host:
        return jsonify({"error": "Could not extract a valid domain from the provided URL"}), 422

    # 3. Queue for admin review (is_approved=False is handled inside add_to_blocklist)
    add_to_blocklist(host, reason=reason)
    
    # 4. Log the report with the real client IP for abuse tracking
    client_ip = get_real_client_ip()
    log.info("Domain queued for review",
             extra={"domain": host, "reason": reason, "ip": client_ip})

    return jsonify({
        "status":  "queued",
        "domain":  host,
        "reason":  reason,
        "message": "Thank you. This domain has been queued for admin review by our security team.",
    }), 200
