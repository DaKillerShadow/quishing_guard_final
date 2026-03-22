"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

from ..engine.resolver   import resolve
from ..engine.scorer     import analyze_url
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog
from ..database          import db
from ..limiter           import limiter
    
bp  = Blueprint("analyse", __name__)

@bp.route("/analyse", methods=["POST"])
@limiter.limit("30 per minute")
def analyse():
    # 1. Parse & validate inbound request
    body    = request.get_json(silent=True) or {}
    raw_url = (body.get("url") or body.get("raw") or "").strip()

    if not raw_url:
        return jsonify({"error": "Missing required field: 'url'"}), 400

    ok, reason = validate_url_payload(raw_url)
    if not ok:
        return jsonify({"error": reason}), 422

    # 2. Initial Reputation Check
    allowlisted = is_allowlisted(raw_url)
    blocklisted = is_blocklisted(raw_url)

    # 3. Resolve redirects
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

    # 4. 🧠 FIXED: Pass the reputation status into the scorer!
    # This ensures that if blocklisted is True, the score is instantly 100.
    result_data = analyze_url(
        url=resolved_url, 
        blocklisted=blocklisted, 
        allowlisted=allowlisted
    )

    # 5. Generate unique Scan ID
    scan_id = hashlib.sha256(
        f"{raw_url}{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:16]

    # 6. Determine the threat label for the database
    if allowlisted:
        threat_text = "None"
    elif blocklisted:
        threat_text = "Reputation Blocklist"
    else:
        threat_text = "Heuristic Detection"

    # 7. Persist to Database (Audit Log)
    try:
        db.session.add(ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result_data['risk_score'],
            risk_label   = result_data['risk_label'],
            top_threat   = threat_text,
            hop_count    = hop_count,
            client_ip    = request.remote_addr,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()

    # 8. Final JSON Response
    return jsonify({
        "id":             scan_id,
        "url":            raw_url,
        "raw_url":        raw_url,         
        "resolved_url":   resolved_url,
        "risk_score":     result_data['risk_score'],
        "risk_label":     result_data['risk_label'],
        "top_threat":     threat_text,
        "redirect_chain": redirect_chain,
        "hop_count":      hop_count,
        "is_allowlisted": allowlisted,
        "is_blocklisted": blocklisted,
        "overall_assessment": result_data['overall_assessment'],
        "analysed_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks":         result_data['checks']
    }), 200
