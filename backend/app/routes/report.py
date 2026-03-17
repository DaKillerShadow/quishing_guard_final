"""
routes/report.py — POST /api/v1/report
========================================
User-facing endpoint. Queues a domain for admin review.

SECURITY CHANGE from v1:
  Old: add_to_blocklist() wrote directly to blocklist.json — unauthenticated
       users could block any domain, including google.com (DoS attack vector).
  New: Submissions are stored with is_approved=False and only become active
       after an admin approves them via the dashboard. Users can no longer
       instantly affect the live blocklist.

Rate limit: 10 per minute per IP.
"""
from __future__ import annotations
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify

from ..engine.reputation import add_to_blocklist
from ..utils.validators  import validate_url_payload
from ..limiter           import limiter
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

    ok, msg = validate_url_payload(url)
    if not ok:
        return jsonify({"error": msg}), 422

    host = urlparse(url if url.startswith("http") else "https://" + url).hostname or ""
    if not host:
        return jsonify({"error": "Could not extract hostname from URL"}), 422

    add_to_blocklist(host, reason=reason)
    log.info("Domain queued for review",
             extra={"domain": host, "reason": reason, "ip": request.remote_addr})

    return jsonify({
        "status":  "queued",
        "domain":  host,
        "reason":  reason,
        "message": "Thank you. This domain has been queued for admin review.",
    }), 200
