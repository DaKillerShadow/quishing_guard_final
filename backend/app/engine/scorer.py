"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.6.1).
Calculates risk scores based on 11 security indicators,
unrolls nested shorteners, and scrapes for HTML evasion.

─────────────────────┬──────┬──────────────────────────────────────────┐
│ Check              │ Pts  │ Threat                                   │
├─────────────────────┼──────┼──────────────────────────────────────────┤
│ nested_short       │  40  │ Multiple URL shorteners chained together │
│ punycode           │  30  │ IDN homograph / brand impersonation      │
│ html_evasion       │  30  │ Hidden HTML meta-refresh redirect        │
│ ip_literal         │  25  │ Raw IP address used instead of domain    │
│ dga_entropy        │  20  │ Machine-generated (DGA) domain name      │
│ redirect_depth     │  20  │ Deep redirect chain cloaking (3+ hops)   │
│ path_keywords      │  15  │ Phishing/Social engineering keywords     │
│ suspicious_tld     │   8  │ Statistically high-risk TLD              │
│ subdomain_depth    │   8  │ Excessive subdomain nesting              │
│ https_mismatch     │   7  │ HTTP used instead of HTTPS               │
├─────────────────────┼──────┼──────────────────────────────────────────┤
│ reputation         │ -50  │ Tranco Top 100k immunity (Score slash)   │
└─────────────────────┴──────┴──────────────────────────────────────────┘
"""
from __future__ import annotations
import time
import re
import os
import requests
import ipaddress
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

# Internal Engine Imports
from .entropy    import dga_score
from .reputation import is_highly_trusted
from .resolver   import resolve

# ── 1. Configuration & Threat Intelligence ────────────────────────────────────

_BAD_TLDS = {
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "live", "online", "site", "website", "space", "fun",
    "zip", "mov", "app", "shop", "info", "work", "vip", "cfd", "sbs", "icu"
}

_PHISHING_KEYWORDS = frozenset({
    # Action keywords
    "login", "signin", "verify", "validation", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin", "identity",
    "vodafone", "fawry", "cib", "bank", "misr", "instapay", "win-prize",
    "uaepass", "tamm", "emirates", "dewa", "adcb", "etisalat", "du-mobile",
    "nafath", "absher", "tawakkalna", "alrajhi", "stc-pay", "saudi-post",
    "aramex", "dhl", "tracking", "parcel", "delivery","proxy", "poxy",
    "proxie", "vpn", "tunnel", "socks", "anon", "bypass", "relay", "mirror",
    "tor", "darkweb", "hide",

    # High-value targets and common phishing path artifacts
    "paypal", "apple", "netflix", "amazon", "microsoft", "google", "meta",
    "cgi-bin", "webscr", "cmd", "billing", "invoice", "refund", "wallet", "account"
})

# NOTE: KNOWN_SHORTENERS is referenced by resolver.py for shortener_count.
# It is intentionally NOT used for scoring here — we rely on trace_data["shortener_count"]
# which comes from the resolver, keeping detection logic in one place.
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
})

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":    65,
    "punycode":      65,
    "dga_entropy":   62,
    "nested_short":  65,
    "html_evasion":  60,
}

# ── 2. AI Threat Analysis Agent ──────────────────────────────────────────────
def get_ai_insight(raw_url: str, resolved_url: str) -> str:
    """
    Evaluates URL contextually using Gemini 1.5 Flash.
    Includes a retry loop for 503 errors and safety overrides for phishing analysis.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "AI analysis disabled. (GEMINI_API_KEY not set in environment)."

    # 1. Prepare the Cybersecurity Prompt
    prompt = (
        f"You are a cybersecurity expert analyzing a scanned QR code URL. "
        f"Original URL: '{raw_url}'. Final Destination: '{resolved_url}'. "
        f"In maximum 2 short sentences, explain if this looks like a phishing/quishing risk and why. "
        f"Do not use markdown, asterisks, or bold text. Plain text only."
    )

    # 2. Configure Payload with Safety Overrides (to prevent censorship of phishing links)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH",        "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT",         "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",  "threshold": "BLOCK_NONE"}
        ]
    }

    # FIX B-01: Corrected model name from "gemini-flash-latest" (invalid) to
    # "gemini-1.5-flash-latest" (the actual Gemini 1.5 Flash stable alias).
    endpoint = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-flash-latest:generateContent?key={api_key}"
    )

    # 3. Execution Loop (Handles 503 Service Unavailable)
    for attempt in range(3):
        try:
            resp = requests.post(endpoint, json=payload, timeout=8)

            # Case A: Success
            if resp.status_code == 200:
                # FIX B-02: Defensive parsing — Gemini can return an empty
                # candidates list when the safety filter blocks the response,
                # or return a malformed payload. The previous code crashed with
                # an unhandled KeyError/IndexError in those cases.
                try:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if not candidates:
                        # Safety filter blocked the response or no candidates returned
                        return "AI analysis unavailable at this time."
                    content_parts = (
                        candidates[0]
                        .get("content", {})
                        .get("parts", [])
                    )
                    if not content_parts:
                        return "AI analysis unavailable at this time."
                    return content_parts[0].get("text", "").strip() or "AI analysis unavailable at this time."
                except (KeyError, IndexError, ValueError) as parse_err:
                    print(f"⚠️ AI response parse error: {parse_err}")
                    return "AI analysis unavailable at this time."

            # Case B: Rate Limit or Server Busy (Retryable)
            if resp.status_code in [429, 503]:
                wait_time = 1.5 * (attempt + 1)
                print(f"🔄 AI Engine busy ({resp.status_code}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue

            # Case C: Critical Errors (Leaked Key 403, etc.) — Stop trying
            print(f"🚨 AI CRITICAL ERROR: {resp.status_code} - {resp.text}")
            break

        except (requests.exceptions.RequestException, Exception) as e:
            print(f"⚠️ Network error on AI call (Attempt {attempt+1}): {str(e)}")
            time.sleep(1)

    return "AI analysis unavailable at this time."

# ── 3. The Unroller (Redirect & Evasion Logic) ───────────────────────────────
def trace_redirects(start_url: str) -> dict:
    """Unmasks the final destination and detects hidden HTML redirects."""
    res = resolve(start_url)

    tracker_results = {
        "hop_count":          res.hop_count,
        "shortener_count":    getattr(res, "shortener_count", 0),  # FIX B-10: guard attribute access
        "final_url":          res.resolved_url,
        "meta_refresh_found": False,
        "error":              res.error,
        "redirect_chain":     getattr(res, "redirect_chain", []),
    }

    if not res.error:
        try:
            with requests.get(
                res.resolved_url, timeout=4, stream=True,
                headers={"User-Agent": "Mozilla/5.0 QuishingGuard/1.0"}
            ) as r:
                chunk = r.raw.read(10000, decode_content=True)
                soup  = BeautifulSoup(chunk, "html.parser")
                if soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
                    tracker_results["meta_refresh_found"] = True
        except (requests.RequestException, OSError):
            pass

    return tracker_results

# ── 4. The 11-Pillar Scoring Engine ──────────────────────────────────────────
def analyse_url(url: str, blocklisted: bool = False, allowlisted: bool = False,
                trace_data: dict | None = None):
    """Calculates the 11-pillar risk score for a given URL."""
    checks = []

    if trace_data is None:
        trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]

    decoded_url = unquote(target_url).lower()
    ext         = tldextract.extract(decoded_url)
    domain      = ext.domain
    full_host   = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".")
    parsed      = urlparse(decoded_url if "://" in decoded_url else "https://" + decoded_url)

    # 1. Global Reputation (The Gatekeeper)
    # FIX B-05: Use "WARNING" (not the ambiguous "UNSAFE") so Flutter's
    # HeuristicCard can map it to the correct amber colour, consistent with
    # the "SAFE" / "WARNING" / "DANGER" contract expected by the frontend.
    is_trusted = is_highly_trusted(domain) or is_highly_trusted(full_host)
    checks.append({
        "name":      "reputation",
        "label":     "GLOBAL REPUTATION",
        "status":    "SAFE" if is_trusted else "WARNING",
        "message":   "Domain recognised in the global Tranco Top 100k reputation list. ✓" if is_trusted
                     else "Domain not found in global reputation database.",
        "metric":    "Tranco Top 100k" if is_trusted else "",
        "score":     -50 if is_trusted else 30,
        "triggered": not is_trusted,
    })

    # 2. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(full_host); is_ip = True
    except ValueError:
        pass
    checks.append({
        "name":      "ip_literal",
        "label":     "IP ADDRESS LITERAL",
        "status":    "DANGER" if is_ip else "SAFE",   # FIX B-05
        "message":   "Link uses a raw IP address instead of a registered domain name." if is_ip
                     else "Link uses a proper registered domain name. ✓",
        "metric":    f"Host: {full_host}" if is_ip else "",
        "score":     25 if is_ip else 0,
        "triggered": is_ip,
    })

    # 3. Punycode/Homograph Attack
    is_puny_encoded  = "xn--" in full_host
    is_unicode_spoof = not full_host.isascii()
    is_puny = is_puny_encoded or is_unicode_spoof
    checks.append({
        "name":      "punycode",
        "label":     "PUNYCODE ATTACK",
        "status":    "DANGER" if is_puny else "SAFE",   # FIX B-05
        "message":   "Punycode (xn--) IDN encoding detected — potential homograph brand impersonation." if is_puny
                     else "No Punycode IDN encoding detected. ✓",
        "metric":    f"Host: {full_host}" if is_puny else "",
        "score":     30 if is_puny else 0,
        "triggered": is_puny,
    })

    # 4. DGA Entropy
    ent_res = dga_score(domain)
    checks.append({
        "name":      "dga_entropy",
        "label":     "DGA ENTROPY ANALYSIS",
        "status":    "DANGER" if ent_res.is_dga else "SAFE",   # FIX B-05
        "message":   f"Domain '{domain}' exhibits machine-generated (DGA) character patterns." if ent_res.is_dga
                     else "Domain entropy is within normal human-chosen name range. ✓",
        "metric":    f"Entropy: {ent_res.entropy:.2f} bits  |  Confidence: {ent_res.confidence}",
        "score":     20 if ent_res.is_dga else 0,
        "triggered": ent_res.is_dga,
    })

    # 5. Phishing Keywords (Path Only)
    path_and_query = (parsed.path + "?" + parsed.query).lower()
    found_kws = [kw for kw in _PHISHING_KEYWORDS if kw in path_and_query]
    checks.append({
        "name":      "path_keywords",
        "label":     "PATH KEYWORDS",
        "status":    "WARNING" if found_kws else "SAFE",   # FIX B-05: keywords → WARNING not DANGER
        "message":   f"Phishing keywords found in URL path: {', '.join(found_kws[:3])}." if found_kws
                     else "No suspicious phishing keywords found in URL path. ✓",
        "metric":    f"Matched: {len(found_kws)} keyword(s)" if found_kws else "",
        "score":     15 if found_kws else 0,
        "triggered": bool(found_kws),
    })

    # 6. Nested Shorteners
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({
        "name":      "nested_short",
        "label":     "NESTED SHORTENERS",
        "status":    "DANGER" if is_nested else "SAFE",   # FIX B-05
        "message":   "Multiple URL shorteners chained together — final destination is deliberately hidden." if is_nested
                     else "No deceptive shortener nesting detected. ✓",
        "metric":    f"Shorteners in chain: {trace_data['shortener_count']}" if trace_data["shortener_count"] else "",
        "score":     40 if is_nested else 0,
        "triggered": is_nested,
    })

    # 7. HTML Evasion
    is_evasion = trace_data["meta_refresh_found"]
    checks.append({
        "name":      "html_evasion",
        "label":     "HTML EVASION",
        "status":    "DANGER" if is_evasion else "SAFE",   # FIX B-05
        "message":   "Hidden HTML meta-refresh redirect detected on the landing page." if is_evasion
                     else "No hidden HTML redirect tags detected. ✓",
        "metric":    "Meta-Refresh tag present" if is_evasion else "",
        "score":     30 if is_evasion else 0,
        "triggered": is_evasion,
    })

    # 8. Redirect Depth
    is_deep = trace_data["hop_count"] >= 3
    checks.append({
        "name":      "redirect_depth",
        "label":     "REDIRECT CHAIN DEPTH",
        "status":    "WARNING" if is_deep else "SAFE",   # FIX B-05: depth → WARNING
        "message":   "Deep redirect chain detected — potential destination cloaking attempt." if is_deep
                     else f"{trace_data['hop_count']} redirect hop(s) followed safely. ✓",
        "metric":    f"Hops: {trace_data['hop_count']}",
        "score":     20 if is_deep else 0,
        "triggered": is_deep,
    })

    # 9. Suspicious TLD
    is_bad_tld = ext.suffix.lower() in _BAD_TLDS
    checks.append({
        "name":      "suspicious_tld",
        "label":     "SUSPICIOUS TLD",
        "status":    "WARNING" if is_bad_tld else "SAFE",   # FIX B-05: TLD → WARNING
        "message":   f"TLD '.{ext.suffix}' has a statistically elevated phishing and abuse history." if is_bad_tld
                     else f"TLD '.{ext.suffix}' is a standard low-risk extension. ✓",
        "metric":    f"TLD: .{ext.suffix}" if is_bad_tld else "",
        "score":     8 if is_bad_tld else 0,
        "triggered": is_bad_tld,
    })

    # 10. Subdomain Nesting
    sub_depth    = len(ext.subdomain.split(".")) if ext.subdomain else 0
    is_deep_sub  = sub_depth >= 3
    checks.append({
        "name":      "subdomain_depth",
        "label":     "SUBDOMAIN DEPTH",
        "status":    "WARNING" if is_deep_sub else "SAFE",   # FIX B-05
        "message":   "Excessive subdomain nesting detected — common phishing technique to mimic trusted brands." if is_deep_sub
                     else "Normal subdomain depth. ✓",
        "metric":    f"Subdomain labels: {sub_depth}" if ext.subdomain else "No subdomains",
        "score":     8 if is_deep_sub else 0,
        "triggered": is_deep_sub,
    })

    # 11. HTTPS Enforcement
    is_http = parsed.scheme == "http"
    checks.append({
        "name":      "https_mismatch",
        "label":     "HTTPS ENFORCEMENT",
        "status":    "WARNING" if is_http else "SAFE",   # FIX B-05
        "message":   "Link uses unencrypted HTTP — data in transit is not protected." if is_http
                     else "Link uses encrypted HTTPS protocol. ✓",
        "metric":    f"Scheme: {parsed.scheme}",
        "score":     7 if is_http else 0,
        "triggered": is_http,
    })

    # ── PHASE 4: FINAL AGGREGATION ────────────────────────────────────────────
    raw_score = sum(c["score"] for c in checks)

    non_reputation_triggered = sum(
        1 for c in checks
        if c["triggered"] and c["name"] != "reputation" and c["score"] > 0
    )

    # 1. Apply base clamping based on reputation
    if is_trusted and not is_puny:
        risk_score = max(0, min(raw_score, 10))
    else:
        risk_score = max(0, min(100, raw_score))

    # 2. Apply Synergy and Critical Floors
    if non_reputation_triggered >= 2:
        risk_score = max(risk_score, 35)

    for c in checks:
        if c["triggered"] and c["name"] in _CRITICAL_OVERRIDE_FLOORS:
            risk_score = max(risk_score, _CRITICAL_OVERRIDE_FLOORS[c["name"]])

    # 3. Apply Hard Overrides (must come last)
    if blocklisted: risk_score = 100
    if allowlisted: risk_score = 0

    final_label = "safe" if risk_score < 30 else "warning" if risk_score < 60 else "danger"

    triggered_checks = [c for c in checks if c["triggered"] and c["score"] > 0]
    top_threat = max(triggered_checks, key=lambda c: c["score"])["label"] if triggered_checks else "None"

    # Call the AI agent
    ai_text = get_ai_insight(url, target_url)

    return {
        "url":                url,
        "resolved_url":       target_url,
        "risk_score":         risk_score,
        "risk_label":         final_label,
        "top_threat":         top_threat,
        "redirect_chain":     trace_data.get("redirect_chain", []),
        "hop_count":          trace_data.get("hop_count", 0),
        "is_allowlisted":     allowlisted,
        "is_blocklisted":     blocklisted,
        "checks":             checks,
        "overall_assessment": "Trusted high-traffic domain." if is_trusted and risk_score < 30
                              else f"Analysis suggests {final_label.upper()}.",
        "ai_analysis":        ai_text,
    }

