"""
scorer.py — Master Integrated Heuristic Scoring Engine (v2.1.2)
======================================================
Core analytical engine for Quishing Guard.
Calculates risk scores based on multi-factor heuristics and 
neutralizes false positives using global reputation data.

─────────────────────┬──────┬──────────────────────────────────────────┐
│ Check               │ Pts  │ Threat                                   │
├─────────────────────┼──────┼──────────────────────────────────────────┤
│ authority_spoofing  │  40  │ Credential mask (@) used for spoofing    │
│ punycode            │  30  │ IDN homograph / brand impersonation      │
│ ip_literal          │  25  │ Raw IP address used instead of domain    │
│ dga_entropy         │  20  │ Machine-generated (DGA) domain name      │
│ redirect_depth      │  20  │ Deep redirect chain cloaking             │
│ nested_short        │  40  │ Deceptive shortener-on-shortener nesting │
│ suspicious_tld      │   8  │ Statistically high-risk TLD              │
└─────────────────────┴──────┴──────────────────────────────────────────┘
False Positive Killer: Tranco Top 100k reduces score by 90%.
"""
from __future__ import annotations
import math
import re
import idna
import ipaddress
import tldextract
from urllib.parse import urlparse, unquote

# Engine Imports
from app.engine.entropy import dga_score
from app.engine.resolver import resolve
from app.engine.reputation import is_highly_trusted

# ── 1. Configuration ──────────────────────────────────────────────────────────

_BAD_TLDS = {
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "live", "online", "site", "website", "space", "fun",
    "zip", "mov", "app", "shop", "info", "work", "vip", "cfd", "sbs", "icu"
}

_PHISHING_PATH_KEYWORDS = frozenset({
    "login", "signin", "verify", "validation", "secure", "update", "reactivate",
    "office365", "outlook", "onedrive", "wp-admin", "webscr", "identity",
    "vodafone-cash", "fawry", "cib-egypt", "banque-misr", "egypt-post", 
    "telecom-egypt", "instapay", "win-prize", "ana-vodafone",
    "uaepass", "tamm", "emirates-post", "dewa", "adcb", "emirates-nbd",
    "etisalat-uae", "du-mobile", "emirates-id", "icp-smart",
    "nafath", "absher", "tawakkalna", "iam-sa", "alrajhi-bank", "snb-alali",
    "stc-pay", "saudi-post", "spl-online", "smsa-delivery", "moj-gov",
    "aramex", "delivery-fees", "track-shipment", "pending-parcel", "dhl-express"
})

_SUSPICIOUS_SLD_KEYWORDS = frozenset({
    "proxy", "poxy", "prxy", "login", "logon", "signin", "log-in", "sign-in",
    "verify", "verif", "verfy", "secure", "secur", "secu", "account", "acct",
    "update", "updat", "confirm", "confrm", "support", "supp0rt", "suspend", 
    "suspended", "alert", "warning", "paypa", "paypai", "paypall", "googl", 
    "g00gle", "micros", "microsooft", "amazn", "amaz0n", "netfl", "netfix",
    "appl", "app1e", "free", "gift", "reward", "bonus", "win", "winner",
    "offer", "deal", "claim", "promo", "help", "helpdesk", "bank", "banking",
})

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "cutt.ly", "is.gd", "buff.ly", "ift.tt",
    "tiny.cc", "lnkd.in", "fb.me", "amzn.to", "adf.ly", "linktr.ee", 
    "lnk.to", "snip.ly", "short.io", "bl.ink", "clck.ru", "qr.ae", 
    "qrco.de", "url.ie", "v.gd", "x.co", "zi.ma",
})

# Weights
W_IP_LITERAL     = 25
W_PUNYCODE       = 30
W_DGA_ENTROPY    = 20
W_REDIRECT_DEPTH = 20
W_SUSPICIOUS_TLD = 8
W_SUBDOMAIN      = 8
W_HTTPS          = 7
W_PATH_KEYWORDS  = 15
W_SLD_KEYWORDS   = 12   
W_URL_SHORTENER  = 15   

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":         65,
    "punycode":           65,
    "dga_entropy":        62,
    "nested_short":       65,
    "authority_spoofing": 65,  
    "blocklist":          100,
}

# ── 2. Helpers ────────────────────────────────────────────────────────────────

def is_short_dga(domain_string: str) -> bool:
    """
    Fallback for domains too short (< 6 chars) for Shannon Entropy.
    Prevents false positives on words like 'strength' or 'netflix'.
    """
    if len(domain_string) >= 6:
        return False
    # Increased to 6 consecutive consonants to reduce false positives
    return bool(re.search(r'[bcdfghjklmnpqrstvwxyz]{6,}', domain_string.lower()))

# ── 3. Main Engine ────────────────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    checks = []
    
    # --- PHASE 1: REDIRECT RESOLUTION ---
    trace_data = resolve(url)
    target_url = trace_data.resolved_url
    chain = trace_data.redirect_chain
    total_hops = trace_data.hop_count

    is_nested = trace_data.shortener_count >= 2
    checks.append({
        "name": "nested_short", "label": "Nested Shorteners",
        "status": "UNSAFE" if is_nested else "SAFE",
        "message": "Multiple URL shorteners detected in a single chain." if is_nested else "No deceptive shortener nesting. ✓",
        "metric": f"Shorteners: {trace_data.shortener_count}", "score": 40 if is_nested else 0, "triggered": is_nested
    })

    is_meta_refresh = trace_data.meta_refresh_found
    checks.append({
        "name": "html_evasion", "label": "HTML Evasion",
        "status": "UNSAFE" if is_meta_refresh else "SAFE",
        "message": "Hidden HTML redirect detected on landing page." if is_meta_refresh else "No hidden HTML redirects. ✓",
        "metric": "", "score": 30 if is_meta_refresh else 0, "triggered": is_meta_refresh
    })

    # --- PHASE 2: ANATOMY EXTRACTION ---
    decoded_target = unquote(target_url).lower()
    ext = tldextract.extract(decoded_target)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_host = ".".join(part for part in [subdomain, domain, suffix] if part)
    
    parsed = urlparse(decoded_target if decoded_target.startswith("http") else "https://" + decoded_target)
    scheme = parsed.scheme.lower()

    # --- PHASE 3: BEHAVIORAL HEURISTICS ---

    # Authority Spoofing (@)
    has_authority_spoof = "@" in parsed.netloc
    checks.append({
        "name": "authority_spoofing", "label": "Authority Spoofing (@ Mask)",
        "status": "UNSAFE" if has_authority_spoof else "SAFE",
        "message": "Credential format (@) used to mask the true domain!" if has_authority_spoof else "No domain masking detected. ✓",
        "metric": "", "score": 40 if has_authority_spoof else 0, "triggered": has_authority_spoof
    })

    # IP Literal
    is_ip = False
    try:
        ipaddress.ip_address(parsed.hostname)
        is_ip = True
    except (ValueError, TypeError): pass
    checks.append({
        "name": "ip_literal", "label": "IP Address Literal",
        "status": "UNSAFE" if is_ip else "SAFE",
        "message": "Link uses a raw IP address instead of a domain name." if is_ip else "Link uses a proper registered domain name. ✓",
        "metric": f"Host: {parsed.hostname}" if is_ip else "",
        "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip
    })

    # Punycode / Homograph
    is_puny = False
    puny_msg = "No Punycode IDN encoding detected. ✓"
    if "xn--" in full_host or re.search(r'[\u0400-\u04FF]', full_host):
        is_puny = True
        puny_msg = "Punycode IDN or Cyrillic characters detected – Homograph risk!"
    checks.append({
        "name": "punycode", "label": "Punycode Attack",
        "status": "UNSAFE" if is_puny else "SAFE",
        "message": puny_msg, "metric": "", "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny
    })

    # DGA Entropy
    entropy_result = dga_score(domain)
    is_dga_threat = entropy_result.is_dga or is_short_dga(domain)
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis",
        "status": "UNSAFE" if is_dga_threat else "SAFE",
        "message": f"Domain '{domain}' shows machine-generated patterns." if is_dga_threat else "Domain entropy is normal. ✓",
        "metric": f"Entropy: {entropy_result.entropy:.2f} bits", 
        "score": W_DGA_ENTROPY if is_dga_threat else 0, "triggered": is_dga_threat
    })

    # Redirects, TLD, Subdomains, HTTPS
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth",
        "status": "UNSAFE" if total_hops >= 3 else "SAFE",
        "message": "Deep redirect chain detected." if total_hops >= 3 else f"{total_hops} hops. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if total_hops >= 3 else 0, "triggered": total_hops >= 3
    })

    is_bad_tld = suffix.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD",
        "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{suffix}' is high-risk." if is_bad_tld else "Standard TLD. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    depth = len(subdomain.split('.')) if subdomain else 0
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth",
        "status": "UNSAFE" if depth >= 3 else "SAFE",
        "message": "Excessive subdomains detected." if depth >= 3 else "Normal depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if depth >= 3 else 0, "triggered": depth >= 3
    })

    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement",
        "status": "UNSAFE" if scheme != "https" else "SAFE",
        "message": "Link uses unencrypted HTTP." if scheme != "https" else "Secure HTTPS. ✓",
        "metric": "", "score": W_HTTPS if scheme != "https" else 0, "triggered": scheme != "https"
    })

    # Keyword Analysis
    scan_target = f"{subdomain.lower()}/{parsed.path.lower()}?{parsed.query.lower()}"
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in scan_target]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords",
        "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Keywords found: {', '.join(matched_kws)}" if path_hit else "No suspicious keywords. ✓",
        "metric": "", "score": W_PATH_KEYWORDS if path_hit else 0, "triggered": path_hit
    })

    sld_lower = domain.lower()
    matched_sld = [kw for kw in _SUSPICIOUS_SLD_KEYWORDS if kw in sld_lower]
    sld_hit = len(matched_sld) >= 1
    checks.append({
        "name": "sld_keywords", "label": "Suspicious Domain Name",
        "status": "UNSAFE" if sld_hit else "SAFE",
        "message": f"Suspicious keyword: {', '.join(matched_sld[:2])}" if sld_hit else "No brand impersonation. ✓",
        "metric": "", "score": W_SLD_KEYWORDS if sld_hit else 0, "triggered": sld_hit
    })

    # --- PHASE 4: REPUTATION OVERRIDE (FALSE POSITIVE KILLER) ---
    is_trusted = is_highly_trusted(domain) or is_highly_trusted(full_host)
    
    # Calculate initial sum
    total_risk = sum(c['score'] for c in checks)
    
    if is_trusted:
        # MASSIVE reduction for high-reputation domains (Tranco Top 100k)
        total_risk = total_risk * 0.1
    
    # Apply Critical Floor Overrides
    for c in checks:
        if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
            # If trusted, the floor shouldn't be as aggressive
            floor = _CRITICAL_OVERRIDE_FLOORS[c['name']]
            if is_trusted: floor *= 0.4 
            total_risk = max(total_risk, floor)
            
    risk_score = min(100, total_risk)

    # Admin overrides
    if blocklisted: risk_score = 100
    elif allowlisted: risk_score = 0

    # Risk Labeling (0-29 Safe, 30-59 Warning, 60+ Danger)
    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 60 else "danger"

    if blocklisted:
        assessment_text = "Known Malicious Domain. Blocked by Administrator."
    elif allowlisted:
        assessment_text = "Trusted Domain. Approved by Administrator."
    elif is_trusted:
        assessment_text = f"Verified high-reputation domain. Heuristic noise suppressed."
    else:
        assessment_text = f"The provided URL appears to be {risk_label.upper()} based on analyzed indicators."

    return {
        "url": url, "resolved_url": target_url,
        "risk_score": int(risk_score), "risk_label": risk_label,
        "checks": checks, "redirect_chain": chain, "hop_count": total_hops,
        "overall_assessment": assessment_text
    }
