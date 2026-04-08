"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.
"""
from __future__ import annotations
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

# The __init__.py facade pattern in action!
from ..engine            import analyze_url, is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id
from ..database          import db
from ..limiter           import limiter, get_real_client_ip
    
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

    # 2. Initial Reputation Check (Surface Level)
    is_initially_allowed = is_allowlisted(raw_url)
    is_initially_blocked = is_blocklisted(raw_url)

    # 3. Master Heuristic Engine
    # We pass the raw_url directly. The scorer will unroll it internally, 
    # ensuring shorteners and HTML evasion are perfectly calculated.
    result_data = analyze_url(
        url=raw_url, 
        blocklisted=is_initially_blocked, 
        allowlisted=is_initially_allowed
    )

    # 4. Deep Reputation Check (The Allowlist Loophole Fix!)
    # Now that the scorer has unrolled the link, we must check if the FINAL destination is blocked.
    resolved_url = result_data['resolved_url']
    final_is_blocked = is_blocklisted(resolved_url)
    final_is_allowed = is_allowlisted(resolved_url)

    # Override the heuristic math if the deep reputation check caught something
    if not is_initially_blocked and final_is_blocked:
        result_data['risk_score'] = 100
        result_data['risk_label'] = 'danger'
        result_data['overall_assessment'] = "Known Malicious Destination. Blocked by Administrator."
        is_initially_blocked = True # Update flag for logging

    elif not is_initially_allowed and final_is_allowed and not is_initially_blocked:
        result_data['risk_score'] = 0
        result_data['risk_label'] = 'safe'
        result_data['overall_assessment'] = "Trusted Destination. Approved by Administrator."
        is_initially_allowed = True # Update flag for logging

    # 5. Determine the threat label for the database
    if is_initially_blocked:
        threat_text = "Reputation Blocklist"
    elif is_initially_allowed:
        threat_text = "None (Trusted)"
    elif result_data['risk_score'] >= 65:
        threat_text = "Heuristic Detection (High)"
    elif result_data['risk_score'] >= 30:
        threat_text = "Heuristic Detection (Warning)"
    else:
        threat_text = "None"

    # 6. Persist to Database (Audit Log)
    scan_id = generate_scan_id()
    try:
        new_log = ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result_data['risk_score'],
            risk_label   = result_data['risk_label'],
            top_threat   = threat_text,
            hop_count    = result_data['hop_count'],
            client_ip    = get_real_client_ip(), 
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Audit log failed for {scan_id}: {e}")

    # 7. Final JSON Response
    return jsonify({
        "id":                 scan_id,
        "url":                raw_url,
        "raw_url":            raw_url,         
        "resolved_url":       resolved_url,
        "risk_score":         result_data['risk_score'],
        "risk_label":         result_data['risk_label'],
        "top_threat":         threat_text,
        "redirect_chain":     result_data['redirect_chain'],
        "hop_count":          result_data['hop_count'],
        "is_allowlisted":     is_initially_allowed,
        "is_blocklisted":     is_initially_blocked,
        "overall_assessment": result_data['overall_assessment'],
        "analysed_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks":             result_data['checks']
    }), 200

