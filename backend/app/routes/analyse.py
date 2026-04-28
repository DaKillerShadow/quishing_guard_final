"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.

Fixes applied (v2.7.0):
  H-1  Pillar #7 (HTML Evasion) was completely non-functional for this
        endpoint. trace_data_for_scorer["meta_refresh_found"] was hard-coded
        to False, meaning no scanned URL could ever trigger the 30-point
        HTML Evasion check through the main /analyse route.

        Root cause: the meta-refresh check lived inside trace_redirects()
        in scorer.py. After the C-1 refactor that eliminated the duplicate
        resolve() call, analyse.py built its own trace_data dict manually
        and simply forgot to run the HTML check.

        Fix: after a successful resolve(), call check_meta_refresh() from
        scorer.py on the resolved URL and store the result in trace_data.
        The HTML check is skipped for allowlisted/blocklisted URLs (the
        verdict is already final and the network call is unnecessary).
"""
from __future__ import annotations
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

from ..engine.resolver   import resolve
from ..engine.scorer     import analyse_url, check_meta_refresh   # H-1 FIX
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

    # ── 3. Resolve redirects ───────────────────────────────────────────────────
    if allowlisted or blocklisted:
        # Verdict already final — no network calls needed.
        resolved_url   = raw_url
        redirect_chain = []
        hop_count      = 0
        trace_data_for_scorer = {
            "hop_count":          0,
            "shortener_count":    0,
            "final_url":          raw_url,
            "redirect_chain":     [],
            "meta_refresh_found": False,   # Skip HTML check for known URLs
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
            #
            # Previously this field was always False because analyse.py built its
            # own trace_data dict and never called check_meta_refresh().  Only
            # scan_image.py (which calls trace_redirects()) ever populated it.
            # Pillar #7 was therefore silent for every URL scanned via this route.
            #
            # check_meta_refresh() fetches only the first 10 KB of the landing
            # page — negligible overhead compared to the resolve() chain above.
            meta_refresh = check_meta_refresh(resolved_url) if not res.error else False

            trace_data_for_scorer = {
                "hop_count":          res.hop_count,
                # FIX B-10 & C-1: Guard shortener_count
                "shortener_count":    getattr(res, "shortener_count", 0),
                "final_url":          res.resolved_url,
                "redirect_chain":     res.redirect_chain,
                "meta_refresh_found": meta_refresh,          # H-1 FIX
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

        # Re-check reputation for final destination if not caught initially
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
