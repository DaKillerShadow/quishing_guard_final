"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.0.0).
Calculates risk scores based on 8 security indicators,
unrolls nested shorteners, and scrapes for HTML evasion.
"""

from __future__ import annotations
import math
import re
import requests
import ipaddress
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ── 1. Configuration & Threat Intelligence ──────────────────────────────────

_BAD_TLDS = {
    "ru","tk","ml","ga","cf","gq","top","xyz","pw","cc",
    "click","download","review","stream","country","kim",
    "icu","live","online","site","website","space","fun", "zip", "mov"
}

_PHISHING_PATH_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "verify", "validation",
    "account-verify", "confirm", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin",
})

# List of domains attackers use to hide their final payloads
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", 
    "is.gd", "cutt.ly", "shorturl.at", "rebrand.ly"
})

# ── 2. Scoring Weights & Critical Floors ─────────────────────────────────────

W_IP_LITERAL     = 25
W_PUNYCODE       = 30
W_DGA_ENTROPY    = 20
W_REDIRECT_DEPTH = 20
W_SUSPICIOUS_TLD = 8
W_SUBDOMAIN      = 8
W_HTTPS          = 7
W_PATH_KEYWORDS  = 15

# If these trigger, the URL is forced to an 'Unsafe' score regardless of others.
_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":   65,   # Raw IP -> unsafe
    "punycode":     65,   # Homograph -> unsafe
    "dga_entropy":  62,   # DGA pattern -> unsafe
    "nested_short": 65,   # Nested Shorteners -> unsafe
}

# ── 3. Analytical Helpers & Unrollers ─────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Implements H(X) = -∑ p(xᵢ) log₂(p(xᵢ)) for DGA detection."""
    if not text: return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

def _parse_domain_parts(url: str):
    """Safely extracts domain parts without corrupting them."""
    ext = tldextract.extract(url)
    raw_domain = f"{ext.domain}.{ext.suffix}"
    # CRITICAL FIX: Using removeprefix instead of lstrip("www.") 
    clean_domain = raw_domain.removeprefix("www.")
    return ext, clean_domain

def trace_redirects(start_url: str) -> dict:
    """Follows URL redirects, checks for nesting, and hunts for HTML meta-refreshes."""
    tracker_results = {
        "hop_count": 0,
        "shortener_count": 0,
        "final_url": start_url,
        "meta_refresh_found": False,
        "redirect_chain": []
    }
    
    try:
        # Use a custom User-Agent to bypass basic bot-blocking
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(start_url, headers=headers, allow_redirects=True, timeout=7)
        
        tracker_results["hop_count"] = len(response.history)
        tracker_results["final_url"] = response.url
        
        # Build the chain list and check for nested shorteners
        for resp in response.history:
            tracker_results["redirect_chain"].append(resp.url)
            ext = tldextract.extract(resp.url)
            domain = f"{ext.domain}.{ext.suffix}"
            if domain in KNOWN_SHORTENERS:
                tracker_results["shortener_count"] += 1
                
        # Scrape the final HTML to see if they hid a meta-refresh redirect
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            tracker_results["meta_refresh_found"] = True
            
    except requests.exceptions.RequestException:
        pass # If connection fails, we just analyze the original start_url
        
    return tracker_results


# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    """
    Evaluates the URL and generates a professional Security Analysis Report.
    Synchronized with Flutter 'SecurityCheck' model fields.
    """
    if allowlisted:
        return {"risk_score": 0, "risk_label": "safe", "checks": [], "overall_assessment": "Trusted Domain.", "resolved_url": url, "redirect_chain": []}
    
    if blocklisted:
        return {"risk_score": 100, "risk_label": "danger", "checks": [], "overall_assessment": "Known Malicious Domain.", "resolved_url": url, "redirect_chain": []}

    checks = []
    
    # --- PHASE 1: THE UNROLLER ---
    trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]
    chain = trace_data["redirect_chain"]
    total_hops = trace_data["hop_count"]

    # Penalty for Nested Shorteners
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({
        "name": "nested_short", "label": "Nested Shorteners",
        "status": "UNSAFE" if is_nested else "SAFE",
        "message": "Multiple URL shorteners detected in a single chain." if is_nested else "No deceptive shortener nesting. ✓",
        "metric": f"Shorteners: {trace_data['shortener_count']}", "score": 40 if is_nested else 0, "triggered": is_nested
    })

    # Penalty for HTML Meta-Refresh
    is_meta_refresh = trace_data["meta_refresh_found"]
    checks.append({
        "name": "html_evasion", "label": "HTML Evasion",
        "status": "UNSAFE" if is_meta_refresh else "SAFE",
        "message": "Hidden HTML redirect detected on landing page." if is_meta_refresh else "No hidden HTML redirects. ✓",
        "metric": "", "score": 30 if is_meta_refresh else 0, "triggered": is_meta_refresh
    })

    # --- PHASE 2: THE ANATOMY ANALYSIS ---

    # A. Extraction using tldextract for accuracy on the TARGET URL
    ext, clean_domain = _parse_domain_parts(target_url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_host = f"{subdomain}.{domain}.{suffix}".strip('.')
    
    parsed = urlparse(target_url if target_url.startswith("http") else "https://" + target_url)
    scheme = parsed.scheme.lower()

    # 1. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError: pass
    
    checks.append({
        "name": "ip_literal", "label": "IP Address Literal",
        "status": "UNSAFE" if is_ip else "SAFE",
        "message": "Link uses a raw IP address instead of a domain name." if is_ip 
                else "Link uses a proper registered domain name. ✓",
        "metric": f"Host: {domain}" if is_ip else "",
        "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip
    })

    # 2. Punycode / Homograph Attack
    is_puny = "xn--" in full_host
    checks.append({
        "name": "punycode", "label": "Punycode Attack",
        "status": "UNSAFE" if is_puny else "SAFE",
        "message": "Punycode IDN encoding detected – potential homograph risk!" if is_puny 
                else "No Punycode IDN encoding detected. ✓",
        "metric": "", "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny
    })

    # 3. DGA Entropy Analysis
    entropy = calculate_entropy(domain)
    is_dga = entropy > 3.65 # Optimized threshold
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis",
        "status": "UNSAFE" if is_dga else "SAFE",
        "message": f"Domain '{domain}' shows machine-generated patterns." if is_dga 
                else "Domain entropy is within normal range. ✓",
        "metric": f"Entropy: {entropy:.2f} bits", 
        "score": W_DGA_ENTROPY if is_dga else 0, "triggered": is_dga
    })

    # 4. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth",
        "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected – potential cloaking attempt." if is_deep_redir 
                else f"{total_hops} redirect hops followed. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
    })

    # 5. Suspicious TLD
    is_bad_tld = suffix.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD",
        "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{suffix}' has an elevated abuse history." if is_bad_tld 
                else f"TLD '.{suffix}' is a standard extension. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    # 6. Excessive Subdomain Depth
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth",
        "status": "UNSAFE" if is_deep_sub else "SAFE",
        "message": "High number of subdomains detected – common in phishing." if is_deep_sub 
                else "Normal domain depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub
    })

    # 7. HTTPS Enforcement
    is_not_https = scheme != "https"
    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement",
        "status": "UNSAFE" if is_not_https else "SAFE",
        "message": "Link uses unencrypted HTTP protocol." if is_not_https 
                else "Link uses encrypted HTTPS protocol. ✓",
        "metric": "", "score": W_HTTPS if is_not_https else 0, "triggered": is_not_https
    })

    # 8. Path Keyword Analysis
    path_lower = parsed.path.lower()
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in path_lower]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords",
        "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Phishing keywords ({', '.join(matched_kws)}) found in path." if path_hit 
                else "No suspicious keywords in path. ✓",
        "metric": "", "score": W_PATH_KEYWORDS if path_hit else 0, "triggered": path_hit
    })

    # Final Aggregation & Overrides
    total_risk = sum(c['score'] for c in checks)
    for c in checks:
        if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
            total_risk = max(total_risk, _CRITICAL_OVERRIDE_FLOORS[c['name']])
            
    risk_score = min(100, total_risk)
    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 65 else "danger"

    return {
        "url": url,
        "resolved_url": target_url,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "checks": checks,
        "redirect_chain": chain,
        "hop_count": total_hops,
        "overall_assessment": f"The provided URL appears to be {risk_label.upper()} based on analyzed indicators."
    }