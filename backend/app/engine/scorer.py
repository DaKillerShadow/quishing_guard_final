"""
scorer.py — Master Integrated Heuristic Scoring Engine (v2.6.4)
================================================================
Core analytical engine for Quishing Guard. Calculates risk scores 
based on 12 security indicators, unrolls nested shorteners, and 
evaluates zero-day infrastructure.

Fixes applied:
  ENG-01  API key redacted from logs; print() replaced with log.error().
  ENG-02  AI call moved to ThreadPoolExecutor to prevent blocking.
  ENG-05  is_trusted uses eTLD+1 only (prevents evil.google.com bypass).
  ENG-06  Unknown reputation scores 0 (not +30) to prevent baseline skew.
  ENG-09  KNOWN_SHORTENERS centralized in resolver.py.
  ENG-11  meta_refresh_found passed from ResolverResult.
  NEW     Pillar 12: Brand Impersonation in Domain detected.
  NEW     Zero-Trust Floor: Unknown domains with 0 triggers default to Warning.
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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

# Internal Engine Imports
from .entropy    import dga_score
from .reputation import is_highly_trusted
from .resolver   import resolve, _is_private
from ..logger    import get_logger

log = get_logger("scorer")

# Single shared executor — limits concurrent AI calls to 4 threads max.
_AI_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ai_worker")

# ── 1. Configuration & Threat Intelligence ────────────────────────────────────

_BAD_TLDS = {
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "live", "online", "site", "website", "space", "fun",
    "zip", "mov", "app", "shop", "info", "work", "vip", "cfd", "sbs", "icu"
}

_PHISHING_KEYWORDS = frozenset({
    "login", "signin", "verify", "validation", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin", "identity",
    "vodafone", "fawry", "cib", "bank", "misr", "instapay", "win-prize",
    "uaepass", "tamm", "emirates", "dewa", "adcb", "etisalat", "du-mobile",
    "nafath", "absher", "tawakkalna", "alrajhi", "stc-pay", "saudi-post",
    "aramex", "dhl", "tracking", "parcel", "delivery", "proxy", "poxy",
    "proxie", "vpn", "tunnel", "socks", "anon", "bypass", "relay", "mirror",
    "tor", "darkweb", "hide",
    "paypal", "apple", "netflix", "amazon", "microsoft", "google", "meta",
    "cgi-bin", "webscr", "cmd", "billing", "invoice", "refund", "wallet", "account"
})

_BRAND_KEYWORDS = frozenset({
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "secure", "verify",
    "account", "billing", "support", "login", "signin", "update",
})

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":   65,
    "punycode":     65,
    "dga_entropy":  62,
    "nested_short": 65,
    "html_evasion": 60,
}

# ── 2. AI Threat Analysis Agent ───────────────────────────────────────────────

def _call_gemini(raw_url: str, resolved_url: str) -> str:
    """Blocking Gemini call — intended to run inside _AI_EXECUTOR."""
    start_time = time.time() # Track when the thread started
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "AI analysis disabled. (GEMINI_API_KEY not set in environment)."

    prompt = (
        f"You are a cybersecurity expert analyzing a scanned QR code URL. "
        f"Original URL: '{raw_url}'. Final Destination: '{resolved_url}'. "
        f"In maximum 2 short sentences, explain if this looks like a phishing/quishing risk and why. "
        f"Do not use markdown, asterisks, or bold text. Plain text only."
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH",        "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT",         "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",  "threshold": "BLOCK_NONE"},
        ],
    }

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-flash-latest:generateContent?key={api_key}"
    )

    for attempt in range(3):
        # 1. Check if we have already exceeded the overall deadline
        if time.time() - start_time > 11.5: 
            log.warning("AI background thread aborting: exceeded 12s deadline.")
            break 

        try:
            resp = requests.post(endpoint, json=payload, timeout=8)

            if resp.status_code == 200:
                try:
                    data           = resp.json()
                    candidates     = data.get("candidates", [])
                    if not candidates:
                        return "AI analysis unavailable at this time."
                    content_parts  = candidates[0].get("content", {}).get("parts", [])
                    if not content_parts:
                        return "AI analysis unavailable at this time."
                    return content_parts[0].get("text", "").strip() or "AI analysis unavailable at this time."
                except (KeyError, IndexError, ValueError) as parse_err:
                    log.warning("AI response parse error: %s", parse_err)
                    return "AI analysis unavailable at this time."

            if resp.status_code in (429, 503):
                wait_time = 1.5 * (attempt + 1)
                
                # 2. Check if sleeping will push us past the deadline
                if time.time() - start_time + wait_time > 11.5:
                    log.warning("AI background thread aborting: sleep will exceed deadline.")
                    break
                    
                log.info("AI Engine busy (%s). Retry %d in %.1fs.", resp.status_code, attempt + 1, wait_time)
                time.sleep(wait_time)
                continue

            log.error("AI critical error: HTTP %s", resp.status_code)
            break

        except requests.exceptions.RequestException as e:
            log.warning("Network error on AI call (attempt %d): %s", attempt + 1, e)
            
            # 3. Prevent the 1-second sleep if time is up
            if time.time() - start_time + 1 > 11.5:
                break
            time.sleep(1)

    return "AI analysis unavailable at this time."


def get_ai_insight(raw_url: str, resolved_url: str) -> str:
    """Submits the Gemini call to a thread pool to prevent blocking."""
    future = _AI_EXECUTOR.submit(_call_gemini, raw_url, resolved_url)
    try:
        return future.result(timeout=12)
    except FuturesTimeout:
        log.warning("AI insight timed out after 12 s — returning fallback.")
        return "AI analysis unavailable at this time."
    except Exception as e:
        log.error("AI executor error: %s", e)
        return "AI analysis unavailable at this time."


# ── 3. The Unroller (Redirect & Evasion Logic) ───────────────────────────────

def check_meta_refresh(url: str) -> bool:
    """Standalone fallback meta-refresh detector with SSRF guard."""
    from urllib.parse import urlparse as _up
    host = (_up(url).hostname or "").lower()
    if not host or _is_private(host):
        log.warning("check_meta_refresh blocked SSRF attempt to host: %s", host)
        return False

    try:
        with requests.get(
            url, timeout=4, stream=True,
            headers={"User-Agent": "Mozilla/5.0 QuishingGuard/1.0"}
        ) as r:
            chunk = r.raw.read(10000, decode_content=True)
            soup  = BeautifulSoup(chunk, "html.parser")
            if soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
                return True
    except (requests.RequestException, OSError):
        pass
    return False


def trace_redirects(start_url: str) -> dict:
    """Unmasks the final destination and detects hidden HTML redirects."""
    res = resolve(start_url)

    tracker_results = {
        "hop_count":          res.hop_count,
        "shortener_count":    getattr(res, "shortener_count", 0),
        "final_url":          res.resolved_url,
        "meta_refresh_found": getattr(res, "meta_refresh_found", False),
        "error":              res.error,
        "redirect_chain":     getattr(res, "redirect_chain", []),
    }
    
    # Fallback check if resolver didn't provide the flag
    if not res.error and not tracker_results["meta_refresh_found"]:
        if hasattr(res, "meta_refresh_found") is False:
            tracker_results["meta_refresh_found"] = check_meta_refresh(res.resolved_url)

    return tracker_results


# ── 4. The 12-Pillar Scoring Engine ──────────────────────────────────────────

def analyse_url(url: str, blocklisted: bool = False, allowlisted: bool = False,
                trace_data: dict | None = None):
    """Calculates the 12-pillar risk score for a given URL."""
    checks = []

    if trace_data is None:
        trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]

    decoded_url = unquote(target_url).lower()
    ext         = tldextract.extract(decoded_url)
    domain      = ext.domain
    etld1       = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ext.domain
    full_host   = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".")
    parsed      = urlparse(decoded_url if "://" in decoded_url else "https://" + decoded_url)

    # 1. Global Reputation (The Gatekeeper)
    is_trusted = is_highly_trusted(etld1)
    checks.append({
        "name":      "reputation",
        "label":     "GLOBAL REPUTATION",
        "status":    "SAFE" if is_trusted else "WARNING",
        "message":   "Domain recognised in the global Tranco Top 100k reputation list. ✓" if is_trusted
                     else "Domain not found in global reputation database.",
        "metric":    "Tranco Top 100k" if is_trusted else "",
        "score":     -50 if is_trusted else 0,
        "triggered": not is_trusted,
    })

    # 2. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(full_host)
        is_ip = True
    except ValueError:
        pass
    checks.append({
        "name":      "ip_literal",
        "label":     "IP ADDRESS LITERAL",
        "status":    "DANGER" if is_ip else "SAFE",
        "message":   "Link uses a raw IP address instead of a registered domain name." if is_ip
                     else "Link uses a proper registered domain name. ✓",
        "metric":    f"Host: {full_host}" if is_ip else "",
        "score":     25 if is_ip else 0,
        "triggered": is_ip,
    })

    # 3. Punycode/Homograph Attack
    is_puny_encoded  = "xn--" in full_host
    is_unicode_spoof = not full_host.isascii()
    is_puny          = is_puny_encoded or is_unicode_spoof
    checks.append({
        "name":      "punycode",
        "label":     "PUNYCODE ATTACK",
        "status":    "DANGER" if is_puny else "SAFE",
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
        "status":    "DANGER" if ent_res.is_dga else "SAFE",
        "message":   f"Domain '{domain}' exhibits machine-generated (DGA) character patterns." if ent_res.is_dga
                     else "Domain entropy is within normal human-chosen name range. ✓",
        "metric":    f"Entropy: {ent_res.entropy:.2f} bits  |  Confidence: {ent_res.confidence}",
        "score":     20 if ent_res.is_dga else 0,
        "triggered": ent_res.is_dga,
    })

    # 5. Phishing Keywords (Path Only)
    path_and_query = (parsed.path + "?" + parsed.query).lower()
    found_kws      = [kw for kw in _PHISHING_KEYWORDS if kw in path_and_query]
    checks.append({
        "name":      "path_keywords",
        "label":     "PATH KEYWORDS",
        "status":    "WARNING" if found_kws else "SAFE",
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
        "status":    "DANGER" if is_nested else "SAFE",
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
        "status":    "DANGER" if is_evasion else "SAFE",
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
        "status":    "WARNING" if is_deep else "SAFE",
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
        "status":    "WARNING" if is_bad_tld else "SAFE",
        "message":   f"TLD '.{ext.suffix}' has a statistically elevated phishing and abuse history." if is_bad_tld
                     else f"TLD '.{ext.suffix}' is a standard low-risk extension. ✓",
        "metric":    f"TLD: .{ext.suffix}" if is_bad_tld else "",
        "score":     8 if is_bad_tld else 0,
        "triggered": is_bad_tld,
    })

    # 10. Subdomain Nesting
    sub_depth   = len(ext.subdomain.split(".")) if ext.subdomain else 0
    is_deep_sub = sub_depth >= 3
    checks.append({
        "name":      "subdomain_depth",
        "label":     "SUBDOMAIN DEPTH",
        "status":    "WARNING" if is_deep_sub else "SAFE",
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
        "status":    "WARNING" if is_http else "SAFE",
        "message":   "Link uses unencrypted HTTP — data in transit is not protected." if is_http
                     else "Link uses encrypted HTTPS protocol. ✓",
        "metric":    f"Scheme: {parsed.scheme}",
        "score":     7 if is_http else 0,
        "triggered": is_http,
    })

    # 12. Brand Impersonation in Domain
    domain_lower    = domain.lower()
    brand_in_domain = any(kw in domain_lower for kw in _BRAND_KEYWORDS)
    is_brand_spoof  = brand_in_domain and not is_trusted
    checks.append({
        "name":      "brand_spoof",
        "label":     "BRAND IMPERSONATION IN DOMAIN",
        "status":    "DANGER" if is_brand_spoof else "SAFE",
        "message":   "Suspicious use of a trusted brand name in an unverified domain." if is_brand_spoof 
                     else "No deceptive brand keywords found in domain. ✓",
        "metric":    f"Domain: {domain}" if is_brand_spoof else "",
        "score":     25 if is_brand_spoof else 0,
        "triggered": is_brand_spoof,
    })

    # ── PHASE 4: FINAL AGGREGATION ────────────────────────────────────────────

    raw_score = sum(c["score"] for c in checks)

    non_reputation_triggered = sum(
        1 for c in checks
        if c["triggered"] and c["name"] != "reputation" and c["score"] > 0
    )

    if is_trusted and not is_puny:
        risk_score = max(0, min(raw_score, 10))
    else:
        risk_score = max(0, min(100, raw_score))

    if non_reputation_triggered >= 2:
        risk_score = max(risk_score, 35)

    for c in checks:
        if c["triggered"] and c["name"] in _CRITICAL_OVERRIDE_FLOORS:
            risk_score = max(risk_score, _CRITICAL_OVERRIDE_FLOORS[c["name"]])

    if allowlisted:
        risk_score = 0
    elif blocklisted:
        risk_score = 100

    final_label = "safe" if risk_score < 30 else "warning" if risk_score < 60 else "danger"

    # ZERO-TRUST FLOOR: Apply warning floor if completely unknown with no triggers
    if not is_trusted and not allowlisted and non_reputation_triggered == 0:
        risk_score  = max(risk_score, 15)
        final_label = "warning"

    triggered_checks = [c for c in checks if c["triggered"] and c["score"] > 0]
    top_threat       = max(triggered_checks, key=lambda c: c["score"])["label"] if triggered_checks else "None"

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
        "is_trusted":         is_trusted,
        "checks":             checks,
        "overall_assessment": (
            "Trusted high-traffic domain." if is_trusted and risk_score < 30
            else "Unverified infrastructure. Proceed with caution." if not is_trusted and risk_score < 30
            else f"Analysis suggests {final_label.upper()}."
        ),
        "ai_analysis":        ai_text,
    }

