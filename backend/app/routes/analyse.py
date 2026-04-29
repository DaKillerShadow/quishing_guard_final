"""
routes/analyse.py — Master API Endpoint (v2.7.3)
=================================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.

Fixes applied:
  RTE-01  KNOWN_SHORTENERS import corrected — now sourced from resolver.py
          (single source of truth).
  RTE-02  Redundant check_meta_refresh() call removed. ResolverResult now
          carries meta_refresh_found, so a second HTTP GET is avoided.
  H-1     HTML Evasion fixed (meta-refresh checking active via ResolverResult).
  H-2     Shortener Bypass fixed — forces resolution of known shorteners
          even if they are highly trusted (Tranco Top 100k).
"""
from __future__ import annotations
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
import tldextract

from ..engine.resolver   import resolve, KNOWN_SHORTENERS   # AUDIT FIX [RTE-01]
from ..engine.scorer     import analyse_url                 # AUDIT FIX [RTE-02]: check_meta_refresh removed
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id
from ..database          import db
from ..limiter           import limiter, get_real_client_ip
from ..logger            import get_logger

bp  = Blueprint("analyse", __name__)
log = get_logger("analyse")


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
    # Shorteners MUST be resolved to expose the hidden payload,
    # even if the shortener domain itself is trusted.
    ext             = tldextract.extract(raw_url)
    domain_to_check = f"{ext.domain}.{ext.suffix}".lower()
    is_shortener    = any(s in domain_to_check for s in KNOWN_SHORTENERS)

    # ── 3. Resolve redirects ───────────────────────────────────────────────────
    # Skip resolving ONLY if it's allowlisted/blocklisted AND NOT a shortener.
    if (allowlisted or blocklisted) and not is_shortener:
        resolved_url          = raw_url
        redirect_chain        = []
        hop_count             = 0
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

            # AUDIT FIX [RTE-02]: Read meta_refresh_found directly from
            # ResolverResult. The previous check_meta_refresh() call made a
            # redundant second HTTP GET to the same host — eliminated here.
            trace_data_for_scorer = {
                "hop_count":          res.hop_count,
                "shortener_count":    res.shortener_count,
                "final_url":          res.resolved_url,
                "redirect_chain":     res.redirect_chain,
                "meta_refresh_found": res.meta_refresh_found,   # ENG-11 + RTE-02 integration
                "error":              res.error,
            }

        except Exception as e:
            log.error("Resolution failed for %s: %s", raw_url, e)
            resolved_url          = raw_url
            redirect_chain        = []
            hop_count             = 0
            trace_data_for_scorer = {
                "hop_count":          0,
                "shortener_count":    0,
                "final_url":          raw_url,
                "redirect_chain":     [],
                "meta_refresh_found": False,
                "error":              str(e),
            }

        # H-2 FIX: Re-evaluate reputation against the FINAL destination.
        # If we kept the shortener's status it could zero out the score.
        allowlisted = is_allowlisted(resolved_url)
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
        log.error("Audit log failed for %s: %s", scan_id, e)

    # ── 8. Final JSON Response ────────────────────────────────────────────────
    return jsonify({
        "id":                 scan_id,
        "url":                raw_url,
        "raw_url":            raw_url,
        "resolved_url":       resolved_url,
        "risk_score":         result_data["risk_score"],
        "risk_label":         result_data["risk_label"],
        "top_threat":         threat_text,
        "redirect_chain":     redirect_chain,
        "hop_count":          hop_count,
        "is_allowlisted":     allowlisted,
        "is_blocklisted":     blocklisted,
        "is_trusted":         result_data.get("is_trusted", False),
        "overall_assessment": result_data["overall_assessment"],
        "ai_analysis":        result_data.get("ai_analysis", "AI analysis unavailable."),
        "analysed_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks":             result_data["checks"],
    }), 200
