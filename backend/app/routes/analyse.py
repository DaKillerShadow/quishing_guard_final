"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.

Fixes applied:
  H-1: HTML Evasion fixed (meta-refresh checking active).
  H-2: Shortener Bypass fixed — Forces resolution of known shorteners 
       even if they are highly trusted (Tranco Top 100k) to expose the payload.
"""
from __future__ import annotations
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
import tldextract

from ..engine.resolver   import resolve
from ..engine.scorer     import analyse_url, check_meta_refresh, KNOWN_SHORTENERS
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id
from ..database          import db
from ..limiter           import limiter, get_real_client_ip

bp = Blueprint("analyse", __name__)


@bp.route("/analyse", methods=["POST"])
@limiter.limit("30 per minute")
def analyse():
    # ── 1. Parse & validate inbound request ───────────────────────────────────
    body    = request.get_json(silent=True) or {}
    raw_url = (body.get("url") or body.get("raw") or "").strip()

    if not raw_url:
        return jsonify({"error": "Missing required field: 'url'"}), 400

    ok, reason = validate_url_payload(raw_url)
    if not ok:
        return jsonify({"error": reason}), 422

    # ── 2. Initial Reputation Check ───────────────────────────────────────────
    allowlisted = is_allowlisted(raw_url)
    blocklisted = is_blocklisted(raw_url)

    # H-2 FIX: Detect if it's a shortener. 
    # Shorteners MUST be resolved to expose the hidden payload, even if the shortener domain is trusted.
    ext = tldextract.extract(raw_url)
    domain_to_check = f"{ext.domain}.{ext.suffix}".lower()
    is_shortener = any(s in domain_to_check for s in KNOWN_SHORTENERS)

    # ── 3. Resolve redirects ───────────────────────────────────────────────────
    # Skip resolving ONLY if it's allowlisted/blocklisted AND NOT a shortener.
    if (allowlisted or blocklisted) and not is_shortener:
        resolved_url   = raw_url
        redirect_chain = []
        hop_count      = 0
        trace_data_for_scorer = {
            "hop_count":          0,
            "shortener_count":    0,
            "final_url":          raw_url,
            "redirect_chain":     [],
            "meta_refresh_found": False,   
            "error":              None,
        }
    else:
        max_hops = current_app.config.get("MAX_REDIRECT_HOPS", 10)
        timeout  = current_app.config.get("RESOLVER_TIMEOUT", 5)

        try:
            res            = resolve(raw_url, max_hops=max_hops, timeout=timeout)
            resolved_url   = res.resolved_url
            redirect_chain = res.redirect_chain
            hop_count      = res.hop_count

            # H-1 FIX: Run the HTML meta-refresh check on the final destination.
            meta_refresh = check_meta_refresh(resolved_url) if not res.error else False

            trace_data_for_scorer = {
                "hop_count":          res.hop_count,
                "shortener_count":    getattr(res, "shortener_count", 0),
                "final_url":          res.resolved_url,
                "redirect_chain":     res.redirect_chain,
                "meta_refresh_found": meta_refresh,          
                "error":              res.error,
            }

        except Exception as e:
            current_app.logger.error(f"Resolution failed for {raw_url}: {e}")
            resolved_url   = raw_url
            redirect_chain = []
            hop_count      = 0
            trace_data_for_scorer = {
                "hop_count":          0,
                "shortener_count":    0,
                "final_url":          raw_url,
                "redirect_chain":     [],
                "meta_refresh_found": False,
                "error":              str(e),
            }

        # H-2 FIX: Always Re-check reputation against the FINAL destination!
        # The shortener might have been trusted, but the final URL might be malicious.
        if not allowlisted:
            allowlisted = is_allowlisted(resolved_url)
        if not blocklisted:
            blocklisted = is_blocklisted(resolved_url)

    # ── 4. Heuristic Analysis ─────────────────────────────────────────────────
    result_data = analyse_url(
        url=raw_url,
        blocklisted=blocklisted,
        allowlisted=allowlisted,
        trace_data=trace_data_for_scorer,
    )

    # ── 5. Generate Scan ID ───────────────────────────────────────────────────
    scan_id = generate_scan_id()

    # ── 6. Determine threat label for the database ────────────────────────────
    if allowlisted:
        threat_text = "None (Trusted)"
    elif blocklisted:
        threat_text = "Reputation Blocklist"
    elif result_data["risk_score"] > 75:
        threat_text = "Heuristic Detection"
    else:
        threat_text = "None"

    # ── 7. Persist to Database (Audit Log) ────────────────────────────────────
    try:
        new_log = ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result_data["risk_score"],
            risk_label   = result_data["risk_label"],
            top_threat   = threat_text,
            hop_count    = hop_count,
            client_ip    = get_real_client_ip(),
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Audit log failed for {scan_id}: {e}")

    # ── 8. Final JSON Response ────────────────────────────────────────────────
    return jsonify({
        "id":             scan_id,
        "url":            raw_url,
        "raw_url":        raw_url,
        "resolved_url":   resolved_url,
        "risk_score":     result_data["risk_score"],
        "risk_label":     result_data["risk_label"],
        "top_threat":     threat_text,
        "redirect_chain": redirect_chain,
        "hop_count":      hop_count,
        "is_allowlisted": allowlisted,
        "is_blocklisted": blocklisted,
        "overall_assessment": result_data["overall_assessment"],
        "ai_analysis":    result_data.get("ai_analysis", "AI analysis unavailable."),
        "analysed_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks":         result_data["checks"],
    }), 200
