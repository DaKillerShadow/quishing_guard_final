"""
routes/analyse.py — Master API Endpoint
==========================================
Main analysis endpoint. Coordinates Resolver, Reputation, and Scorer.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

import requests as http_requests
from bs4 import BeautifulSoup

from ..engine.resolver   import resolve
from ..engine.scorer     import analyse_url
from ..engine.reputation import is_allowlisted, is_blocklisted
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id
from ..database          import db
from ..limiter           import limiter, get_real_client_ip

bp = Blueprint("analyse", __name__)


def _check_meta_refresh(url: str) -> bool:
    """
    FIX B-03: Performs the HTML meta-refresh check that was previously only
    inside scorer.trace_redirects(). When analyse.py pre-builds trace_data
    (to avoid a duplicate resolve() call), it must also compute this flag —
    otherwise the HTML Evasion pillar (30 pts) was permanently disabled.

    Returns True if a meta-refresh tag is found on the landing page.
    """
    try:
        with http_requests.get(
            url, timeout=4, stream=True,
            headers={"User-Agent": "Mozilla/5.0 QuishingGuard/1.0"}
        ) as r:
            chunk = r.raw.read(10000, decode_content=True)
            soup  = BeautifulSoup(chunk, "html.parser")
            return bool(
                soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
            )
    except (http_requests.RequestException, OSError):
        return False


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

        # FIX C-1 & UI: build a neutral trace payload — no network call needed
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
            res = resolve(raw_url, max_hops=max_hops, timeout=timeout)
            resolved_url   = res.resolved_url
            redirect_chain = res.redirect_chain
            hop_count      = res.hop_count

            # FIX B-03: Actually fetch meta-refresh from the resolved page so
            # the HTML Evasion pillar can fire. Previously this was hardcoded
            # to False, silently disabling 30 pts of detection.
            meta_refresh = _check_meta_refresh(resolved_url) if not res.error else False

            # FIX B-10 & C-1: Guard shortener_count and capture all trace fields
            trace_data_for_scorer = {
                "hop_count":          res.hop_count,
                "shortener_count":    getattr(res, "shortener_count", 0),
                "final_url":          res.resolved_url,
                "redirect_chain":     res.redirect_chain,
                "meta_refresh_found": meta_refresh,   # FIX B-03
                "error":              res.error,
            }
        except Exception as e:
            current_app.logger.error(f"Resolution failed for {raw_url}: {e}")
            resolved_url   = raw_url
            redirect_chain = []
            hop_count      = 0

            # FIX C-1 & UI: fallback trace data when resolution fails entirely
            trace_data_for_scorer = {
                "hop_count":          0,
                "shortener_count":    0,
                "final_url":          raw_url,
                "redirect_chain":     [],
                "meta_refresh_found": False,
                "error":              str(e),
            }

        # Re-check reputation for final destination if it wasn't caught initially
        if not allowlisted:
            allowlisted = is_allowlisted(resolved_url)
        if not blocklisted:
            blocklisted = is_blocklisted(resolved_url)

    # 4. Heuristic Analysis (Passes reputation flags for weighted scoring)
    # FIX C-1: Pass pre-computed trace_data so analyse_url() skips its internal
    # trace_redirects() call — eliminates the duplicate resolve() that
    # previously fired on every scan, halving network cost and SSRF surface.
    result_data = analyse_url(
        url=raw_url,
        blocklisted=blocklisted,
        allowlisted=allowlisted,
        trace_data=trace_data_for_scorer,  # FIX C-1
    )

    # 5. Use consistent Scan ID generation
    scan_id = generate_scan_id()

    # 6. Determine the threat label for the database
    if allowlisted:
        threat_text = "None (Trusted)"
    elif blocklisted:
        threat_text = "Reputation Blocklist"
    elif result_data["risk_score"] > 75:
        threat_text = "Heuristic Detection"
    else:
        threat_text = "None"

    # 7. Persist to Database (Audit Log)
    try:
        new_log = ScanLog(
            id           = scan_id,
            raw_url      = raw_url,
            resolved_url = resolved_url,
            risk_score   = result_data["risk_score"],
            risk_label   = result_data["risk_label"],
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
        "raw_url":        raw_url,          # kept for backward compat
        "resolved_url":   resolved_url,
        "risk_score":     result_data["risk_score"],
        "risk_label":     result_data["risk_label"],
        "top_threat":     threat_text,
        "redirect_chain": redirect_chain,
        "hop_count":      hop_count,
        "is_allowlisted": allowlisted,
        "is_blocklisted": blocklisted,
        "overall_assessment": result_data["overall_assessment"],
        "ai_analysis":    result_data.get("ai_analysis", "AI analysis unavailable."), # ✅ ADDED: Pass AI result to Flutter!
        "analysed_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks":         result_data["checks"],
    }), 200
