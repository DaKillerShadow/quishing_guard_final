"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.0.0).
Calculates risk scores based on 8 security indicators.
"""

from __future__ import annotations
import math
import re
import ipaddress
import tldextract
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
}

# ── 3. Analytical Helpers ─────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Implements H(X) = -∑ p(xᵢ) log₂(p(xᵢ)) for DGA detection."""
    if not text: return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, hop_count: int = 0, blocklisted: bool = False, allowlisted: bool = False):
    """
    Evaluates the URL and generates a professional Security Analysis Report.
    Synchronized with Flutter 'SecurityCheck' model fields.
    """
    if allowlisted:
        return {"risk_score": 0, "risk_label": "safe", "checks": [], "overall_assessment": "Trusted Domain."}
    
    if blocklisted:
        return {"risk_score": 100, "risk_label": "danger", "checks": [], "overall_assessment": "Known Malicious Domain."}

    # A. Extraction using tldextract for accuracy
    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_host = f"{subdomain}.{domain}.{suffix}".strip('.')
    
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    scheme = parsed.scheme.lower()
    
    checks = []

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
    is_deep_redir = hop_count >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth",
        "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected – potential cloaking attempt." if is_deep_redir 
                else f"{hop_count} redirect hops followed. ✓",
        "metric": f"Hops: {hop_count}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
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
        "resolved_url": url,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "checks": checks,
        "overall_assessment": f"The provided URL appears to be {risk_label.upper()} based on analyzed indicators."
    }