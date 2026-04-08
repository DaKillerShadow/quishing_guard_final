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
import idna
import requests
import ipaddress
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

# Imports for Quishing Guard modules
from app.engine.entropy import dga_score
from app.engine.reputation import is_highly_trusted
from .resolver import resolve  # Enterprise safe resolver

# ── 1. Configuration & Regional Intelligence ──────────────────────────────────

_BAD_TLDS = {
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "live", "online", "site", "website", "space", "fun",
    "zip", "mov", "app", "shop", "info", "work", "vip", "cfd", "sbs", "icu"
}

_PHISHING_KEYWORDS = frozenset({
    # Universal
    "login", "signin", "verify", "validation", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin", "identity",
    # Regional (Egypt, UAE, KSA)
    "vodafone", "fawry", "cib", "bank", "misr", "instapay", "win-prize", 
    "uaepass", "tamm", "emirates", "dewa", "adcb", "etisalat", "du-mobile",
    "nafath", "absher", "tawakkalna", "alrajhi", "stc-pay", "saudi-post",
    # Logistics
    "aramex", "dhl", "tracking", "parcel", "delivery"
})

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
})

# ── 2. Weights & Critical Floors ─────────────────────────────────────────────

W_IP_LITERAL     = 25
W_PUNYCODE       = 30
W_DGA_ENTROPY    = 20
W_REDIRECT_DEPTH = 20
W_PATH_KEYWORDS  = 15
W_TLD_RISK       = 8
W_SUBDOMAIN      = 8
W_HTTPS          = 7

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":    65,
    "punycode":      65,
    "dga_entropy":   62,
    "nested_short":  65,
}

# ── 3. Helper Functions (Redirect Unroller) ───────────────────────────────────

def trace_redirects(start_url: str) -> dict:
    """
    Traces URL redirects using the safe resolver to prevent SSRF and TOCTOU attacks.
    Performs a final GET request to check for HTML meta-refresh evasion.
    """
    # 1. Run the enterprise resolver (HEAD requests only, strictly safe)
    res = resolve(start_url)
    
    tracker_results = {
        "hop_count": res.hop_count,
        "shortener_count": 0,
        "final_url": res.resolved_url,
        "meta_refresh_found": False,
        "redirect_chain": res.redirect_chain,
        "error": res.error
    }

    # 2. Count shorteners using the new chain
    for url in res.redirect_chain:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        if domain in KNOWN_SHORTENERS:
            tracker_results["shortener_count"] += 1

    # 3. HTML Evasion Check (Only on the final resolved URL)
    if not res.error and res.status_code == 200:
        try:
            # We use GET here just once to check the body of the final page
            final_resp = requests.get(
                res.resolved_url, 
                timeout=5, 
                stream=True,
                # Disguise the final GET request as well to prevent blocking
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'}
            )
            chunk = final_resp.raw.read(50_000, decode_content=True)
            soup = BeautifulSoup(chunk, 'html.parser')
            
            # Search for meta-refresh tags
            if soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)}):
                tracker_results["meta_refresh_found"] = True
        except:
            pass

    return tracker_results

# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    checks = []

    # --- PHASE 1: THE UNROLLER (Active Scanning) ---
    trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]
    total_hops = trace_data["hop_count"]

    # --- PHASE 2: ANATOMY EXTRACTION ---
    decoded_url = unquote(target_url).lower()
    ext = tldextract.extract(decoded_url)
    domain = ext.domain
    full_host = ".".join(part for part in [ext.subdomain, domain, ext.suffix] if part)
    parsed = urlparse(decoded_url if "://" in decoded_url else "https://" + decoded_url)

    # --- PHASE 3: THE 11 PILLARS ---

    # 1. Global Reputation (Tranco Killer)
    is_trusted = is_highly_trusted(domain) or is_highly_trusted(full_host)
    checks.append({
        "name": "reputation", "label": "GLOBAL REPUTATION", 
        "status": "SAFE" if is_trusted else "WARNING",
        "message": "Domain verified in Tranco Top 100k. ✓" if is_trusted else "Domain not found in global trusted lists.",
        "score": -50 if is_trusted else 0, "triggered": not is_trusted, "metric": "Verified" if is_trusted else "Unranked"
    })

    # 2. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(domain); is_ip = True
    except: pass
    checks.append({"name": "ip_literal", "label": "IP ADDRESS LITERAL", "status": "UNSAFE" if is_ip else "SAFE", 
                   "message": "Link uses a raw IP address." if is_ip else "Link uses a proper domain name. ✓", 
                   "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip, "metric": ""})

    # 3. Punycode Attack
    is_puny = "xn--" in full_host or re.search(r'[\u0400-\u04FF]', full_host)
    checks.append({"name": "punycode", "label": "PUNYCODE ATTACK", "status": "UNSAFE" if is_puny else "SAFE", 
                   "message": "Homograph risk detected." if is_puny else "No Punycode encoding detected. ✓", 
                   "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny, "metric": ""})

    # 4. DGA Entropy Analysis (Normalized)
    ent_res = dga_score(domain)
    checks.append({"name": "dga_entropy", "label": "DGA ENTROPY ANALYSIS", "status": "UNSAFE" if ent_res.is_dga else "SAFE", 
                   "message": "Domain entropy indicates DGA pattern." if ent_res.is_dga else "Entropy is within normal range. ✓", 
                   "score": W_DGA_ENTROPY if ent_res.is_dga else 0, "triggered": ent_res.is_dga, "metric": f"Entropy: {ent_res.entropy} bits"})

    # 5. Phishing Keywords (Whole Host + Path)
    found_kws = [kw for kw in _PHISHING_KEYWORDS if kw in full_host or kw in parsed.path]
    has_kw = bool(found_kws)
    checks.append({"name": "path_keywords", "label": "PATH KEYWORDS", "status": "UNSAFE" if has_kw else "SAFE", 
                   "message": f"Detected: {', '.join(found_kws[:2])}" if has_kw else "No suspicious keywords. ✓", 
                   "score": W_PATH_KEYWORDS if has_kw else 0, "triggered": has_kw, "metric": ""})

    # 6. Nested Shorteners
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({"name": "nested_short", "label": "NESTED SHORTENERS", "status": "UNSAFE" if is_nested else "SAFE", 
                   "message": "Multiple shorteners detected." if is_nested else "No deceptive shortener nesting. ✓", 
                   "score": 40 if is_nested else 0, "triggered": is_nested, "metric": f"Count: {trace_data['shortener_count']}"})

    # 7. HTML Evasion
    is_evasion = trace_data["meta_refresh_found"]
    checks.append({"name": "html_evasion", "label": "HTML EVASION", "status": "UNSAFE" if is_evasion else "SAFE", 
                   "message": "Hidden HTML redirect detected." if is_evasion else "No hidden HTML redirects. ✓", 
                   "score": 30 if is_evasion else 0, "triggered": is_evasion, "metric": ""})

    # 8. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({"name": "redirect_depth", "label": "REDIRECT CHAIN DEPTH", "status": "UNSAFE" if is_deep_redir else "SAFE", 
                   "message": "Deep redirect chain detected." if is_deep_redir else "Normal hop count. ✓", 
                   "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir, "metric": f"Hops: {total_hops}"})

    # 9. Suspicious TLD
    is_bad_tld = ext.suffix.lower() in _BAD_TLDS
    checks.append({"name": "suspicious_tld", "label": "SUSPICIOUS TLD", "status": "UNSAFE" if is_bad_tld else "SAFE", 
                   "message": f"TLD '.{ext.suffix}' is high-risk." if is_bad_tld else f"TLD '.{ext.suffix}' is standard. ✓", 
                   "score": W_TLD_RISK if is_bad_tld else 0, "triggered": is_bad_tld, "metric": ""})

    # 10. Subdomain Depth
    sub_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    is_deep_sub = sub_count >= 3
    checks.append({"name": "subdomain_depth", "label": "SUBDOMAIN DEPTH", "status": "UNSAFE" if is_deep_sub else "SAFE", 
                   "message": "Excessive subdomains found." if is_deep_sub else "Normal domain depth. ✓", 
                   "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub, "metric": f"Labels: {sub_count + 2}"})

    # 11. HTTPS Enforcement
    is_http = parsed.scheme == "http"
    checks.append({"name": "https_mismatch", "label": "HTTPS ENFORCEMENT", "status": "UNSAFE" if is_http else "SAFE", 
                   "message": "Unencrypted HTTP protocol." if is_http else "Encrypted HTTPS protocol. ✓", 
                   "score": W_HTTPS if is_http else 0, "triggered": is_http, "metric": ""})

    # --- PHASE 4: FINAL AGGREGATION ---
    total_risk = sum(c['score'] for c in checks)
    
    # Trusted sites immunity (unless Punycode is used)
    if is_trusted and not is_puny:
        total_risk = min(total_risk, 10)

    risk_score = max(0, min(100, int(total_risk)))
    
    # Critical Floors for non-trusted domains
    if not is_trusted:
        for c in checks:
            if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
                risk_score = max(risk_score, _CRITICAL_OVERRIDE_FLOORS[c['name']])

    if blocklisted: risk_score = 100
    if allowlisted: risk_score = 0

    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 60 else "danger"

    return {
        "url": url, 
        "resolved_url": target_url, 
        "risk_score": risk_score, 
        "risk_label": risk_label,
        "checks": checks, 
        "overall_assessment": "Trusted high-traffic domain." if is_trusted else f"Analysis suggests {risk_label.upper()}."
    }