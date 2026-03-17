"""
routes/analyse.py — POST /api/v1/analyse
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.
Updated to sync with Flutter 'SecurityCheck' model fields.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

from ..engine.resolver   import resolve
from ..engine.scorer     import score
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog
from ..database          import db
from ..limiter           import limiter
from ..logger            import get_logger

bp  = Blueprint("analyse", __name__) # URL prefix is handled in factory (__init__.py)
log = get_logger("analyse")

@bp.route("/analyse", methods=["POST"])
@limiter.limit("30 per minute")
def analyse():
    # 1. Parse & validate
    body    = request.get_json(silent=True) or {}
    raw_url = (body.get("url") or body.get("raw") or "").strip()

    if not raw_url:
        return jsonify({"error": "Missing required field: 'url'"}), 400

    ok, reason = validate_url_payload(raw_url)
    if not ok:
        return jsonify({"error": reason}), 422

    # 2. Reputation fast-paths
    allowlisted = is_allowlisted(raw_url)
    blocklisted = is_blocklisted(raw_url)

    # 3. Resolve redirects (The "Eyes")
    if allowlisted:
        resolved_url   = raw_url
        redirect_chain = []
        hop_count      = 0
    else:
        max_hops = current_app.config.get("MAX_REDIRECT_HOPS", 10)
        timeout  = current_app.config.get("RESOLVER_TIMEOUT", 5)
        res = resolve(raw_url, max_hops=max_hops, timeout=timeout)
        resolved_url   = res.resolved_url
        redirect_chain = res.redirect_chain
        hop_count      = res.hop_count

        # Re-check reputation for final destination
        if not allowlisted:
            allowlisted = is_allowlisted(resolved_url)
        if not blocklisted:
            blocklisted = is_blocklisted(resolved_url)

    # 4. Score (The "Brain")
    result = score(
        resolved_url   = resolved_url,
        raw_url        = raw_url,
        redirect_chain = redirect_chain,
        hop_count      = hop_count,
        allowlisted    = allowlisted,
        blocklisted    = blocklisted,
    )

    # 5. Stable scan ID for audit logs
    scan_id = hashlib.sha256(
        f"{raw_url}{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:16]

    # 6. Persist to audit log
    try:
        db.session.add(ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result.risk_score,
            risk_label   = result.risk_label,
            top_threat   = result.top_threat,
            hop_count    = hop_count,
            client_ip    = request.remote_addr,
        ))
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.error("Failed to write scan log", extra={"exc": str(exc)})

    # 7. Build Response (SYCHRONIZED WITH FLUTTER)
    return jsonify({
        "id":             scan_id,
        "raw_url":        raw_url,
        "url":            raw_url, # Alias for model compatibility
        "resolved_url":   resolved_url,
        "risk_score":     result.risk_score,
        "risk_label":     result.risk_label,
        "top_threat":     result.top_threat,
        "redirect_chain": redirect_chain,
        "hop_count":      hop_count,
        "is_allowlisted": allowlisted,
        "is_blocklisted": blocklisted,
        "overall_assessment": f"The provided URL appears to be {result.risk_label.upper()}.",
        "analysed_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks": [
            {
                "name":        c.name,
                "label":       c.label,
                "status":      "UNSAFE" if c.triggered else "SAFE", # Mapped for Flutter
                "triggered":   c.triggered,
                "score":       c.score,
                "message":     c.description, # Mapped for Flutter
                "metric":      c.detail or "", # Mapped for Flutter
            }
            for c in result.checks
        ],
    }), 200