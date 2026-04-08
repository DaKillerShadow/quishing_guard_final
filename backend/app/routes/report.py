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

# BUG FIX: Imported is_allowlisted to prevent "Trusted Domain Trolling"
from ..engine            import add_to_blocklist, is_allowlisted
from ..engine.reputation import _get_etld1  # Internal helper for extraction
from ..utils.validators  import validate_url_payload
from ..limiter           import limiter, get_real_client_ip 
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

    # 2. Trusted Domain Trolling Guard
    # Prevent users from flooding the admin queue with reports for Google, Apple, etc.
    if is_allowlisted(url):
        log.warning("Attempted to report an allowlisted domain", extra={"url": url, "ip": get_real_client_ip()})
        return jsonify({"error": "This domain is a verified trusted system domain and cannot be reported."}), 403

    # 3. Standardize the domain/host extraction
    host = _get_etld1(url)
    if not host:
        return jsonify({"error": "Could not extract a valid domain from the provided URL"}), 422

    # 4. Queue for admin review
    client_ip = get_real_client_ip()
    
    # Passing the IP so the admin dashboard shows WHO reported it (Abuse tracking)
    add_to_blocklist(host, reason=reason, reporter_ip=client_ip) 
    
    # 5. Log the report
    log.info("Domain queued for review",
             extra={"domain": host, "reason": reason, "ip": client_ip})

    return jsonify({
        "status":  "queued",
        "domain":  host,
        "reason":  reason,
        "message": "Thank you. This domain has been queued for admin review by our security team.",
    }), 200
