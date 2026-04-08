"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.
"""
from __future__ import annotations
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

from ..engine.resolver   import resolve
from ..engine.scorer     import analyse_url
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id # Import the generator
from ..database          import db
from ..limiter           import limiter, get_real_client_ip # Use our IP helper
    
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
    # OPTIMIZED: Skip resolution if we already know it's Safe OR Dangerous
    if allowlisted or blocklisted:
        resolved_url   = raw_url
        redirect_chain = []
        hop_count      = 0
    else:
        max_hops = current_app.config.get("MAX_REDIRECT_HOPS", 10)
        timeout  = current_app.config.get("RESOLVER_TIMEOUT", 5)
        
        try:
            res = resolve(raw_url, max_hops=max_hops, timeout=timeout)
            resolved_url   = res.resolved_url
            redirect_chain = res.redirect_chain
            hop_count      = res.hop_count
        except Exception as e:
            current_app.logger.error(f"Resolution failed for {raw_url}: {e}")
            resolved_url = raw_url
            redirect_chain = []
            hop_count = 0

        # Re-check reputation for final destination if it wasn't caught initially
        if not allowlisted:
            allowlisted = is_allowlisted(resolved_url)
        if not blocklisted:
            blocklisted = is_blocklisted(resolved_url)

    # 4. Heuristic Analysis (Passes reputation flags for weighted scoring)
    result_data = analyse_url(
        url=resolved_url, 
        blocklisted=blocklisted, 
        allowlisted=allowlisted
    )

    # 5. Use consistent Scan ID generation
    scan_id = generate_scan_id()

    # 6. Determine the threat label for the database
    if allowlisted:
        threat_text = "None (Trusted)"
    elif blocklisted:
        threat_text = "Reputation Blocklist"
    elif result_data['risk_score'] > 75:
        threat_text = "Heuristic Detection"
    else:
        threat_text = "None"

    # 7. Persist to Database (Audit Log)
    try:
        new_log = ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result_data['risk_score'],
            risk_label   = result_data['risk_label'],
            top_threat   = threat_text,
            hop_count    = hop_count,
            client_ip    = get_real_client_ip(), # Fixed: Log real user IP
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Audit log failed for {scan_id}: {e}")

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
