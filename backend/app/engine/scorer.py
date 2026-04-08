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
import ipaddress
import tldextract
from urllib.parse import urlparse, unquote

# Import your dedicated modules
from app.engine.entropy import dga_score
from app.engine.resolver import resolve

# ── 1. Configuration & Regional Threat Intel ──────────────────────────────────

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

# ── 2. Scoring Weights & Critical Floors ─────────────────────────────────────

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
    "authority_spoofing": 65,  # ADDED: Instantly flag @ spoofs
    "blocklist":          100,
}

# ── 3. Helper Functions ───────────────────────────────────────────────────────

def is_short_dga(domain_string: str) -> bool:
    """Secondary check for short DGA domains (e.g. x7z9q2mwpb) that bypass entropy limitations."""
    # Matches if there are 5 or more consecutive consonants or numbers
    if re.search(r'[bcdfghjklmnpqrstvwxyz0-9]{5,}', domain_string.lower()):
        return True
    return False

# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    """
    Evaluates the URL and generates a professional Security Analysis Report.
    Synchronized with Flutter 'SecurityCheck' model fields.
    """
    checks = []
    
    # --- PHASE 1: THE UNROLLER ---
    # Call the external resolver microservice
    trace_data = resolve(url)
    
    # Extract data using the dataclass dot-notation
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

    # --- PHASE 2: THE ANATOMY ANALYSIS ---
    # 1. DEEP URL DECODING (Defeats Percent Encoding Masking)
    decoded_target = unquote(target_url).lower()
    
    ext = tldextract.extract(decoded_target)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_host = ".".join(part for part in [subdomain, domain, suffix] if part)
    
    parsed = urlparse(decoded_target if decoded_target.startswith("http") else "https://" + decoded_target)
    scheme = parsed.scheme.lower()

    # 2. AUTHORITY SPOOFING CHECK (Defeats the "@" Trap)
    # The netloc contains the credentials if they exist (e.g., fake.com@real.com)
    has_authority_spoof = "@" in parsed.netloc
    checks.append({
        "name": "authority_spoofing", "label": "Authority Spoofing (@ Mask)",
        "status": "UNSAFE" if has_authority_spoof else "SAFE",
        "message": "Credential format (@) used to mask the true domain!" if has_authority_spoof else "No domain masking detected. ✓",
        "metric": "", "score": 40 if has_authority_spoof else 0, "triggered": has_authority_spoof
    })

    # 3. IP ADDRESS LITERAL (Now defeats Hex/Dword/Octal masks!)
    is_ip = False
    try:
        # parsed.hostname cleanly extracts the host, even if it's an integer
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

    # 4. Punycode / Homograph / Cyrillic Attack
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
        except Exception: pass

    checks.append({
        "name": "punycode", "label": "Punycode Attack",
        "status": "UNSAFE" if is_puny else "SAFE",
        "message": puny_msg,
        "metric": "", "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny
    })

    # 5. DGA Entropy Analysis
    entropy_result = dga_score(domain)
    is_dga_threat = entropy_result.is_dga or is_short_dga(domain)
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis",
        "status": "UNSAFE" if is_dga_threat else "SAFE",
        "message": f"Domain '{domain}' shows machine-generated patterns." if is_dga_threat else "Domain entropy is within normal range. ✓",
        "metric": f"Entropy: {entropy_result.entropy:.2f} bits", 
        "score": W_DGA_ENTROPY if is_dga_threat else 0, "triggered": is_dga_threat
    })

    # 6. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth",
        "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected – potential cloaking attempt." if is_deep_redir else f"{total_hops} redirect hops followed. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
    })

    # 7. Suspicious TLD
    is_bad_tld = suffix.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD",
        "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{suffix}' has an elevated abuse history." if is_bad_tld else f"TLD '.{suffix}' is a standard extension. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    # 8. Excessive Subdomain Depth
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth",
        "status": "UNSAFE" if is_deep_sub else "SAFE",
        "message": "High number of subdomains detected – common in phishing." if is_deep_sub else "Normal domain depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub
    })

    # 9. HTTPS Enforcement
    is_not_https = scheme != "https"
    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement",
        "status": "UNSAFE" if is_not_https else "SAFE",
        "message": "Link uses unencrypted HTTP protocol." if is_not_https else "Link uses encrypted HTTPS protocol. ✓",
        "metric": "", "score": W_HTTPS if is_not_https else 0, "triggered": is_not_https
    })

    # 10. Path & Subdomain Keyword Analysis 
    # Updated to catch keywords in the URL parameters as well
scan_target = f"{subdomain.lower()}/{parsed.path.lower()}?{parsed.query.lower()}"
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in scan_target]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords",
        "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Phishing keywords ({', '.join(matched_kws)}) found in URL." if path_hit else "No suspicious keywords. ✓",
        "metric": "", "score": W_PATH_KEYWORDS if path_hit else 0, "triggered": path_hit
    })

    # 11. SLD Keyword Analysis
    sld_lower = domain.lower()
    matched_sld = [kw for kw in _SUSPICIOUS_SLD_KEYWORDS if kw in sld_lower]
    sld_hit = len(matched_sld) >= 1
    checks.append({
        "name": "sld_keywords", "label": "Suspicious Domain Name",
        "status": "UNSAFE" if sld_hit else "SAFE",
        "message": f"Domain name contains suspicious keyword(s): {', '.join(matched_sld[:3])}." if sld_hit else "No brand impersonation patterns. ✓",
        "metric": "", "score": W_SLD_KEYWORDS if sld_hit else 0, "triggered": sld_hit
    })

    # 12. URL Shortener Detection
    etld1 = f"{domain}.{suffix}".lower()
    short_hit = etld1 in KNOWN_SHORTENERS or full_host.lower() in KNOWN_SHORTENERS
    short_hit = short_hit and total_hops == 0
    checks.append({
        "name": "url_shortener", "label": "URL Shortener (Hidden Destination)",
        "status": "UNSAFE" if short_hit else "SAFE",
        "message": f"URL shortener '{etld1}' hides the final destination." if short_hit else "Destination is directly visible. ✓",
        "metric": "", "score": W_URL_SHORTENER if short_hit else 0, "triggered": short_hit
    })

    # ── FINAL AGGREGATION & OVERRIDES ──
    total_risk = sum(c['score'] for c in checks)
    for c in checks:
        if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
            total_risk = max(total_risk, _CRITICAL_OVERRIDE_FLOORS[c['name']])
            
    risk_score = min(100, total_risk)

    if blocklisted:
        risk_score = 100
    elif allowlisted:
        risk_score = 0

    triggered_names = [c['name'] for c in checks if c['triggered']]
    if "suspicious_tld" in triggered_names and "sld_keywords" in triggered_names and not (blocklisted or allowlisted):
        risk_score = max(risk_score, 35)

    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 65 else "danger"

    if blocklisted:
        assessment_text = "Known Malicious Domain. Blocked by Administrator."
    elif allowlisted:
        assessment_text = "Trusted Domain. Approved by Administrator."
    else:
        assessment_text = f"The provided URL appears to be {risk_label.upper()} based on analyzed indicators."

    return {
        "url": url,
        "resolved_url": target_url,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "checks": checks,
        "redirect_chain": chain,
        "hop_count": total_hops,
        "overall_assessment": assessment_text
    }

