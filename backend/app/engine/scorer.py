"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.0.0).
Calculates risk scores based on 8 security indicators,
unrolls nested shorteners, and scrapes for HTML evasion.
─────────────────────┬──────┬──────────────────────────────────────────┐
│ Check               │ Pts  │ Threat                                   │
├─────────────────────┼──────┼──────────────────────────────────────────┤
│ ip_literal          │  25  │ Raw IP address used instead of domain    │
│ punycode            │  30  │ IDN homograph / brand impersonation      │
│ dga_entropy         │  20  │ Machine-generated (DGA) domain name      │
│ redirect_depth      │  20  │ Deep redirect chain cloaking             │
│ suspicious_tld      │   8  │ Statistically high-risk TLD              │
│ subdomain_depth     │   8  │ Excessive subdomain nesting              │
│ https_mismatch      │   7  │ HTTP used instead of HTTPS               │
└─────────────────────┴──────┴──────────────────────────────────────────┘
Maximum raw:  118  →  capped at 100
Risk labels:
  0–29  safe    — green,  proceed with caution
 30–59  warning — amber,  micro-lesson triggered, confirmation required
 60–100 danger  — red,    blocked by default, explicit override needed
"""

from __future__ import annotations
import math
import re
import idna
import requests
import ipaddress
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ── 1. Configuration & Regional Threat Intel ──────────────────────────────────

_BAD_TLDS = {
    # Global high-abuse TLDs
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "icu", "live", "online", "site", "website", "space", "fun",
    # New high-risk extensions (often used for fake 'apps' or local scams)
    "zip", "mov", "app", "shop", "info", "work", "vip", "cfd", "sbs", "icu"
}

_PHISHING_PATH_KEYWORDS = frozenset({
    # Universal Keywords
    "login", "signin", "verify", "validation", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin", "webscr", "identity",
    
    # 🇪🇬 Egypt Specific (Wallets & Services)
    "vodafone-cash", "fawry", "cib-egypt", "banque-misr", "egypt-post", 
    "telecom-egypt", "instapay", "win-prize", "ana-vodafone",
    
    # 🇦🇪 UAE Specific (Identity & Logistics)
    "uaepass", "tamm", "emirates-post", "dewa", "adcb", "emirates-nbd",
    "etisalat-uae", "du-mobile", "emirates-id", "icp-smart",
    
    # 🇸🇦 Saudi Arabia Specific (Government Portals)
    "nafath", "absher", "tawakkalna", "iam-sa", "alrajhi-bank", "snb-alali",
    "stc-pay", "saudi-post", "spl-online", "smsa-delivery", "moj-gov",
    
    # 📦 Regional Logistics (Major Phishing Lure)
    "aramex", "delivery-fees", "track-shipment", "pending-parcel", "dhl-express"
})

# Patterns that are 99% indicative of phishing in the region
_COMPOUND_PATTERNS = (
    "paypal-account", "microsoft-login", "apple-id", "google-account",
    "amazon-verify", "office365-login", "outlook-signin", "netflix-account",
    # Regional Compounds
    "nafath-verify", "absher-login", "uaepass-auth", "vodafone-cash-reward",
    "aramex-payment", "emirates-post-parcel", "fawry-pay", "stc-pay-otp"
)

# ── 2. Scoring Weights & Critical Floors ─────────────────────────────────────

W_IP_LITERAL     = 25
W_PUNYCODE       = 30
W_DGA_ENTROPY    = 20
W_REDIRECT_DEPTH = 20
W_SUSPICIOUS_TLD = 8
W_SUBDOMAIN      = 8
W_HTTPS          = 7
W_PATH_KEYWORDS  = 15

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":   65,
    "punycode":     65,
    "dga_entropy":  62,
    "nested_short": 65,
    "blocklist":    100,
}

# ── 3. Helper Functions ───────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect DGA (Domain Generation Algorithms)."""
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def trace_redirects(start_url: str) -> dict:
    """Follows URL redirects, mimics an iPhone, and hunts for HTML meta-refreshes."""
    tracker_results = {
        "hop_count": 0,
        "shortener_count": 0,
        "final_url": start_url,
        "meta_refresh_found": False,
        "redirect_chain": []
    }
    
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) '
            'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'
        ),
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    try:
        response = requests.get(
            start_url, 
            headers=headers, 
            allow_redirects=True, 
            timeout=10,
            verify=True
        )
        
        tracker_results["hop_count"] = len(response.history)
        tracker_results["final_url"] = response.url
        
        for resp in response.history:
            tracker_results["redirect_chain"].append(resp.url)
            ext = tldextract.extract(resp.url)
            domain = f"{ext.domain}.{ext.suffix}"
            if domain in KNOWN_SHORTENERS:
                tracker_results["shortener_count"] += 1
                
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        
        if meta_refresh:
            tracker_results["meta_refresh_found"] = True
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                tracker_results["final_url"] = content.lower().split('url=')[1].strip(' "\'')
            
    except requests.exceptions.RequestException:
        pass 
        
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
    ext = tldextract.extract(target_url)
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
        "message": "Link uses a raw IP address instead of a domain name." if is_ip else "Link uses a proper registered domain name. ✓",
        "metric": f"Host: {domain}" if is_ip else "",
        "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip
    })

    # 2. Punycode / Homograph / Cyrillic Attack
    is_puny = False
    puny_msg = "No Punycode IDN encoding detected. ✓"

    if "xn--" in full_host:
        is_puny = True
        puny_msg = "Punycode (xn--) IDN encoding detected – potential homograph risk!"
    elif re.search(r'[\u0400-\u04FF]', full_host):
        is_puny = True
        puny_msg = "Cyrillic homograph characters detected – high phishing risk!"
    else:
        try:
            encoded_domain = idna.encode(domain).decode('ascii')
            if "xn--" in encoded_domain and encoded_domain != domain:
                is_puny = True
                puny_msg = "Hidden IDN/Homograph encoding detected."
        except Exception:
            pass

    checks.append({
        "name": "punycode", "label": "Punycode Attack",
        "status": "UNSAFE" if is_puny else "SAFE",
        "message": puny_msg,
        "metric": "", 
        "score": W_PUNYCODE if is_puny else 0, 
        "triggered": is_puny
    })

    # 3. DGA Entropy Analysis
    entropy = calculate_entropy(domain)
    is_dga = entropy > 3.65
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis",
        "status": "UNSAFE" if is_dga else "SAFE",
        "message": f"Domain '{domain}' shows machine-generated patterns." if is_dga else "Domain entropy is within normal range. ✓",
        "metric": f"Entropy: {entropy:.2f} bits", 
        "score": W_DGA_ENTROPY if is_dga else 0, "triggered": is_dga
    })

    # 4. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth",
        "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected – potential cloaking attempt." if is_deep_redir else f"{total_hops} redirect hops followed. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
    })

    # 5. Suspicious TLD
    is_bad_tld = suffix.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD",
        "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{suffix}' has an elevated abuse history." if is_bad_tld else f"TLD '.{suffix}' is a standard extension. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    # 6. Excessive Subdomain Depth
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth",
        "status": "UNSAFE" if is_deep_sub else "SAFE",
        "message": "High number of subdomains detected – common in phishing." if is_deep_sub else "Normal domain depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub
    })

    # 7. HTTPS Enforcement
    is_not_https = scheme != "https"
    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement",
        "status": "UNSAFE" if is_not_https else "SAFE",
        "message": "Link uses unencrypted HTTP protocol." if is_not_https else "Link uses encrypted HTTPS protocol. ✓",
        "metric": "", "score": W_HTTPS if is_not_https else 0, "triggered": is_not_https
    })

    # 8. Path Keyword Analysis
    path_lower = parsed.path.lower()
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in path_lower]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords",
        "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Phishing keywords ({', '.join(matched_kws)}) found in path." if path_hit else "No suspicious keywords in path. ✓",
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