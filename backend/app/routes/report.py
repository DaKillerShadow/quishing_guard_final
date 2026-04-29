"""
routes/report.py — POST /api/v1/report (v2.7.3)
================================================
User-facing endpoint. Queues a domain for admin review.

Submissions are stored with is_approved=False and only become active
after an admin approves them via the dashboard. Users cannot instantly
affect the live blocklist.

Fixes applied (Batch 2):
  RTE-05  url_prefix removed from Blueprint() constructor — single source
          of truth is register_blueprint() in __init__.py.
  RTE-06  add_to_blocklist() return value checked. After Batch 1 fix ENG-18
          makes it return bool, ignoring the value meant DB write failures
          were silently swallowed and the user received a false HTTP 200
          "queued" confirmation. Now returns HTTP 500 on failure.
"""
from __future__ import annotations
from flask import Blueprint, request, jsonify

from ..engine.reputation import add_to_blocklist, _get_etld1
from ..utils.validators  import validate_url_payload
from ..limiter           import limiter, get_real_client_ip
from ..logger            import get_logger

# AUDIT FIX [RTE-05]: url_prefix removed from constructor.
bp  = Blueprint("report", __name__)
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

    host = _get_etld1(url)
    if not host:
        return jsonify({
            "error": "Could not extract a valid domain from the provided URL"
        }), 422

    # AUDIT FIX [RTE-06]: Check the bool return value from add_to_blocklist().
    # Before this fix, a DB write failure returned HTTP 200 "queued" — giving
    # the user false confirmation that their report was received.
    success = add_to_blocklist(host, reason=reason)
    if not success:
        log.error("Failed to queue domain for review: %s", host)
        return jsonify({
            "error": "Failed to queue report — please try again later."
        }), 500

    client_ip = get_real_client_ip()
    log.info(
        "Domain queued for review",
        extra={"domain": host, "reason": reason, "ip": client_ip},
    )

    return jsonify({
        "status":  "queued",
        "domain":  host,
        "reason":  reason,
        "message": "Thank you. This domain has been queued for admin review by our security team.",
    }), 200
