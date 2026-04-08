"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.6.0).
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

* Maximum raw score: 203 → capped at 100
* Critical Floors: Triggering specific high-risk pillars (like IP Literal 
  or Nested Shorteners) instantly elevates the score to 65+ (Danger).

Risk labels:
  0–29  safe    — green,  proceed with caution
 30–59  warning — amber,  micro-lesson triggered, confirmation required
 60–100 danger  — red,    blocked by default, explicit override needed
"""
from __future__ import annotations
import re
import requests
import ipaddress
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

# Internal Engine Imports
from app.engine.entropy import dga_score
from app.engine.reputation import is_highly_trusted
from .resolver import resolve 

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
    "aramex", "dhl", "tracking", "parcel", "delivery"
})

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

# ── 2. The Unroller (Redirect & Evasion Logic) ───────────────────────────────

def trace_redirects(start_url: str) -> dict:
    """Unmasks the final destination and detects hidden HTML redirects."""
    # 1. Resolve network-level hops (301/302)
    res = resolve(start_url)
    
    tracker_results = {
        "hop_count": res.hop_count,
        "shortener_count": res.shortener_count,
        "final_url": res.resolved_url,
        "meta_refresh_found": False,
        "error": res.error
    }

    # 2. Scrape for Client-Side Evasion (Meta-Refresh)
    if not res.error:
        try:
            # Minimal stream to save bandwidth on Render
            with requests.get(res.resolved_url, timeout=4, stream=True, 
                              headers={'User-Agent': 'Mozilla/5.0 QuishingGuard/1.0'}) as r:
                chunk = r.raw.read(10000, decode_content=True)
                soup = BeautifulSoup(chunk, 'html.parser')
                if soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)}):
                    tracker_results["meta_refresh_found"] = True
        except:
            pass

    return tracker_results

# ── 3. The 11-Pillar Scoring Engine ──────────────────────────────────────────

def analyse_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    """Calculates the 11-pillar risk score for a given URL."""
    checks = []

    # PHASE 1: Resolve Deception
    trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]
    
    # PHASE 2: Anatomy Extraction
    decoded_url = unquote(target_url).lower()
    ext = tldextract.extract(decoded_url)
    domain = ext.domain
    full_host = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".")
    parsed = urlparse(decoded_url if "://" in decoded_url else "https://" + decoded_url)

    # --- THE 11 PILLARS ---

    # 1. Global Reputation (The Gatekeeper)
    is_trusted = is_highly_trusted(domain) or is_highly_trusted(full_host)
    checks.append({"name": "reputation", "label": "GLOBAL REPUTATION", "score": -50 if is_trusted else 0, "triggered": not is_trusted})

    # 2. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(domain); is_ip = True
    except: pass
    checks.append({"name": "ip_literal", "label": "IP ADDRESS LITERAL", "score": 25 if is_ip else 0, "triggered": is_ip})

    # 3. Punycode/Homograph Attack
    is_puny = "xn--" in full_host
    checks.append({"name": "punycode", "label": "PUNYCODE ATTACK", "score": 30 if is_puny else 0, "triggered": is_puny})

    # 4. DGA Entropy (Shannon Math)
    ent_res = dga_score(domain)
    checks.append({"name": "dga_entropy", "label": "DGA ENTROPY ANALYSIS", "score": 20 if ent_res.is_dga else 0, "triggered": ent_res.is_dga})

    # 5. Phishing Keywords
    found_kws = [kw for kw in _PHISHING_KEYWORDS if kw in decoded_url]
    checks.append({"name": "path_keywords", "label": "PATH KEYWORDS", "score": 15 if found_kws else 0, "triggered": bool(found_kws)})

    # 6. Nested Shorteners
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({"name": "nested_short", "label": "NESTED SHORTENERS", "score": 40 if is_nested else 0, "triggered": is_nested})

    # 7. HTML Evasion
    is_evasion = trace_data["meta_refresh_found"]
    checks.append({"name": "html_evasion", "label": "HTML EVASION", "score": 30 if is_evasion else 0, "triggered": is_evasion})

    # 8. Redirect Depth
    is_deep = trace_data["hop_count"] >= 3
    checks.append({"name": "redirect_depth", "label": "REDIRECT CHAIN DEPTH", "score": 20 if is_deep else 0, "triggered": is_deep})

    # 9. Suspicious TLD
    is_bad_tld = ext.suffix.lower() in _BAD_TLDS
    checks.append({"name": "suspicious_tld", "label": "SUSPICIOUS TLD", "score": 8 if is_bad_tld else 0, "triggered": is_bad_tld})

    # 10. Subdomain Nesting
    sub_depth = len(ext.subdomain.split('.')) if ext.subdomain else 0
    checks.append({"name": "subdomain_depth", "label": "SUBDOMAIN DEPTH", "score": 8 if sub_depth >= 3 else 0, "triggered": sub_depth >= 3})

    # 11. HTTPS Enforcement
    is_http = parsed.scheme == "http"
    checks.append({"name": "https_mismatch", "label": "HTTPS ENFORCEMENT", "score": 7 if is_http else 0, "triggered": is_http})

    # --- PHASE 4: FINAL AGGREGATION ---
    raw_score = sum(c['score'] for c in checks)
    
    if is_trusted and not is_puny:
        risk_score = min(raw_score, 10)
    else:
        risk_score = max(0, min(100, raw_score))
        for c in checks:
            if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
                risk_score = max(risk_score, _CRITICAL_OVERRIDE_FLOORS[c['name']])

    if blocklisted: risk_score = 100
    if allowlisted: risk_score = 0

    # ✅ Define the label once for the dictionary and the assessment string
    final_label = "safe" if risk_score < 30 else "warning" if risk_score < 60 else "danger"

    # ✅ THE FIX: Ensure all keys exist for analyse.py
    return {
        "url": url, 
        "resolved_url": target_url, 
        "risk_score": risk_score, 
        "risk_label": final_label,
        "checks": checks, 
        "overall_assessment": "Trusted high-traffic domain." if is_trusted else f"Analysis suggests {final_label.upper()}."
    }