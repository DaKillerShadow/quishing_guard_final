"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.0.0).
Calculates risk scores based on 10 security indicators,
unrolls nested shorteners, and detects hidden destinations.
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
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "icu", "live", "online", "site", "website", "space", "fun",
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

_COMPOUND_PATTERNS = (
    "paypal-account", "microsoft-login", "apple-id", "google-account",
    "amazon-verify", "office365-login", "outlook-signin", "netflix-account",
    "nafath-verify", "absher-login", "uaepass-auth", "vodafone-cash-reward",
    "aramex-payment", "emirates-post-parcel", "fawry-pay", "stc-pay-otp"
)

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
})

_SUSPICIOUS_SLD_KEYWORDS: frozenset[str] = frozenset({
    "proxy", "poxy", "prxy", "login", "logon", "signin", "log-in", "sign-in",
    "verify", "verif", "verfy", "secure", "secur", "secu", "account", "acct",
    "update", "updat", "confirm", "confrm", "support", "supp0rt", "suspend", 
    "suspended", "alert", "warning", "paypa", "paypai", "paypall", "googl", 
    "g00gle", "micros", "microsooft", "amazn", "amaz0n", "netfl", "netfix", 
    "appl", "app1e", "free", "gift", "reward", "bonus", "win", "winner",
    "offer", "deal", "claim", "promo", "help", "helpdesk", "bank", "banking",
})

# ── Addition 2: Shortener domain set ──────────────────────────────────────────
_URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "cutt.ly", "is.gd", "buff.ly", "ift.tt",
    "tiny.cc", "lnkd.in", "fb.me", "youtu.be", 
    "amzn.to", "adf.ly", "linktr.ee", "lnk.to", "snip.ly", "short.io", 
    "bl.ink", "clck.ru", "qr.ae", "qrco.de", "url.ie", "v.gd", "x.co", "zi.ma",
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
W_URL_SHORTENER  = 15   # Addition 1: Weight constant

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":   65,
    "punycode":     65,
    "dga_entropy":  62,
    "nested_short": 65,
    "blocklist":    100,
    "url_shortener": 30,  # Addition 4: Override floor
}

# ── 3. Helper Functions ───────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def trace_redirects(start_url: str) -> dict:
    tracker_results = {
        "hop_count": 0, "shortener_count": 0, "final_url": start_url,
        "meta_refresh_found": False, "redirect_chain": []
    }
    headers = {
        'User-Agent': ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) '
                       'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'),
    }
    try:
        response = requests.get(start_url, headers=headers, allow_redirects=True, timeout=10)
        tracker_results["hop_count"] = len(response.history)
        tracker_results["final_url"] = response.url
        for resp in response.history:
            tracker_results["redirect_chain"].append(resp.url)
            ext = tldextract.extract(resp.url)
            if f"{ext.domain}.{ext.suffix}" in KNOWN_SHORTENERS:
                tracker_results["shortener_count"] += 1
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            tracker_results["meta_refresh_found"] = True
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                tracker_results["final_url"] = content.lower().split('url=')[1].strip(' "\'')
    except Exception: pass
    return tracker_results

# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    if allowlisted: return {"risk_score": 0, "risk_label": "safe", "checks": [], "resolved_url": url}
    if blocklisted: return {"risk_score": 100, "risk_label": "danger", "checks": [], "resolved_url": url}

    checks = []
    trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]
    total_hops = trace_data["hop_count"]

    # --- PHASE 1: THE UNROLLER ---
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({
        "name": "nested_short", "label": "Nested Shorteners",
        "status": "UNSAFE" if is_nested else "SAFE",
        "message": "Multiple URL shorteners detected in a single chain." if is_nested else "No deceptive shortener nesting. ✓",
        "metric": f"Shorteners: {trace_data['shortener_count']}", "score": 40 if is_nested else 0, "triggered": is_nested
    })

    is_meta_refresh = trace_data["meta_refresh_found"]
    checks.append({
        "name": "html_evasion", "label": "HTML Evasion",
        "status": "UNSAFE" if is_meta_refresh else "SAFE",
        "message": "Hidden HTML redirect detected on landing page." if is_meta_refresh else "No hidden HTML redirects. ✓",
        "metric": "", "score": 30 if is_meta_refresh else 0, "triggered": is_meta_refresh
    })

    # --- PHASE 2: THE ANATOMY ANALYSIS ---
    ext = tldextract.extract(target_url)
    sld, tld = ext.domain, ext.suffix
    subdomain = ext.subdomain
    full_host = f"{subdomain}.{sld}.{tld}".strip('.')
    
    parsed = urlparse(target_url if target_url.startswith("http") else "https://" + target_url)
    scheme = parsed.scheme.lower()

    # 1. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(sld)
        is_ip = True
    except ValueError: pass
    checks.append({
        "name": "ip_literal", "label": "IP Address Literal", "status": "UNSAFE" if is_ip else "SAFE",
        "message": "Link uses a raw IP address instead of a domain name." if is_ip else "Proper domain name used. ✓",
        "metric": f"Host: {sld}" if is_ip else "", "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip
    })

    # 2. Punycode Attack
    is_puny = "xn--" in full_host or re.search(r'[\u0400-\u04FF]', full_host)
    checks.append({
        "name": "punycode", "label": "Punycode Attack", "status": "UNSAFE" if is_puny else "SAFE",
        "message": "Hidden IDN/Homograph encoding detected." if is_puny else "No Punycode IDN encoding detected. ✓",
        "metric": "", "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny
    })

    # 3. DGA Entropy
    entropy = calculate_entropy(sld)
    is_dga = entropy > 3.65
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis", "status": "UNSAFE" if is_dga else "SAFE",
        "message": f"Domain '{sld}' shows machine-generated patterns." if is_dga else "Normal domain entropy. ✓",
        "metric": f"{entropy:.2f} bits", "score": W_DGA_ENTROPY if is_dga else 0, "triggered": is_dga
    })

    # 4. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth", "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected." if is_deep_redir else f"{total_hops} hops followed. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
    })

    # 5. Suspicious TLD
    is_bad_tld = tld.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD", "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{tld}' has a high abuse history." if is_bad_tld else f"Standard TLD '.{tld}'. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    # 6. Subdomain Depth
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth", "status": "UNSAFE" if is_deep_sub else "SAFE",
        "message": "High subdomain count detected." if is_deep_sub else "Normal domain depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub
    })

    # 7. HTTPS Enforcement
    is_not_https = scheme != "https"
    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement", "status": "UNSAFE" if is_not_https else "SAFE",
        "message": "Link uses unencrypted HTTP." if is_not_https else "Link uses HTTPS. ✓",
        "metric": "", "score": W_HTTPS if is_not_https else 0, "triggered": is_not_https
    })

    # 8. Path Keywords
    path_lower = parsed.path.lower()
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in path_lower]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords", "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Phishing keywords found in path." if path_hit else "No suspicious keywords in path. ✓",
        "metric": "", "score": W_PATH_KEYWORDS if path_hit else 0, "triggered": path_hit
    })

    # 9. SLD Keywords
    sld_lower = sld.lower()
    matched_sld = [kw for kw in _SUSPICIOUS_SLD_KEYWORDS if kw in sld_lower]
    sld_hit = len(matched_sld) >= 1
    checks.append({
        "name": "sld_keywords", "label": "Suspicious Domain Name", "status": "UNSAFE" if sld_hit else "SAFE",
        "message": f"Domain contains suspicious keyword(s): {', '.join(matched_sld[:3])}." if sld_hit else "No brand impersonation patterns. ✓",
        "metric": "", "score": W_SLD_KEYWORDS if sld_hit else 0, "triggered": sld_hit
    })

    # ── Addition 3: Check 10: URL Shortener Detection ────────────────────────────
    etld1 = f"{sld}.{tld}".lower()
    hostname = full_host.lower()
    hop_count = total_hops
    
    short_hit = etld1 in _URL_SHORTENERS or hostname in _URL_SHORTENERS
    short_hit = short_hit and hop_count == 0
    
    checks.append({
        "name": "url_shortener",
        "label": "URL Shortener (Hidden Destination)",
        "status": "UNSAFE" if short_hit else "SAFE",
        "triggered": short_hit,
        "score": W_URL_SHORTENER if short_hit else 0,
        "message": (
            f"This QR code uses the URL shortener '{etld1}' to hide the final destination. "
            "URL shorteners in QR codes are a primary quishing technique — the victim cannot "
            "inspect where the link leads without scanning it. The resolver could not follow "
            "this redirect to reveal the true destination."
        ) if short_hit else (
            "No URL shortener detected — destination is directly visible. ✓"
            if etld1 not in _URL_SHORTENERS
            else "URL shortener detected but redirect was followed successfully — final destination scored. ✓"
        ),
        "metric": f"Shortener: {etld1}" if short_hit else ""
    })

    # ── Composite score ──────────────────────────────────────────────────────────
    total_risk = sum(c['score'] for c in checks)
    for c in checks:
        if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
            total_risk = max(total_risk, _CRITICAL_OVERRIDE_FLOORS[c['name']])
            
    risk_score = min(100, total_risk)
    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 65 else "danger"

    return {
        "url": url, "resolved_url": target_url, "risk_score": risk_score,
        "risk_label": risk_label, "checks": checks, "redirect_chain": trace_data["redirect_chain"],
        "hop_count": total_hops, "overall_assessment": f"The URL is {risk_label.upper()}."
    }
"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (v2.0.0).
Calculates risk scores based on 10 security indicators,
unrolls nested shorteners, and detects hidden destinations.
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
    "ru", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "pw", "cc",
    "click", "download", "review", "stream", "country", "kim",
    "icu", "live", "online", "site", "website", "space", "fun",
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

_COMPOUND_PATTERNS = (
    "paypal-account", "microsoft-login", "apple-id", "google-account",
    "amazon-verify", "office365-login", "outlook-signin", "netflix-account",
    "nafath-verify", "absher-login", "uaepass-auth", "vodafone-cash-reward",
    "aramex-payment", "emirates-post-parcel", "fawry-pay", "stc-pay-otp"
)

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
})

_SUSPICIOUS_SLD_KEYWORDS: frozenset[str] = frozenset({
    "proxy", "poxy", "prxy", "login", "logon", "signin", "log-in", "sign-in",
    "verify", "verif", "verfy", "secure", "secur", "secu", "account", "acct",
    "update", "updat", "confirm", "confrm", "support", "supp0rt", "suspend", 
    "suspended", "alert", "warning", "paypa", "paypai", "paypall", "googl", 
    "g00gle", "micros", "microsooft", "amazn", "amaz0n", "netfl", "netfix", 
    "appl", "app1e", "free", "gift", "reward", "bonus", "win", "winner",
    "offer", "deal", "claim", "promo", "help", "helpdesk", "bank", "banking",
})

# ── Addition 2: Shortener domain set ──────────────────────────────────────────
_URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "cutt.ly", "is.gd", "buff.ly", "ift.tt",
    "tiny.cc", "lnkd.in", "fb.me", "youtu.be", 
    "amzn.to", "adf.ly", "linktr.ee", "lnk.to", "snip.ly", "short.io", 
    "bl.ink", "clck.ru", "qr.ae", "qrco.de", "url.ie", "v.gd", "x.co", "zi.ma",
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
W_URL_SHORTENER  = 15   # Addition 1: Weight constant

_CRITICAL_OVERRIDE_FLOORS = {
    "ip_literal":   65,
    "punycode":     65,
    "dga_entropy":  62,
    "nested_short": 65,
    "blocklist":    100,
    "url_shortener": 30,  # Addition 4: Override floor
}

# ── 3. Helper Functions ───────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def trace_redirects(start_url: str) -> dict:
    tracker_results = {
        "hop_count": 0, "shortener_count": 0, "final_url": start_url,
        "meta_refresh_found": False, "redirect_chain": []
    }
    headers = {
        'User-Agent': ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) '
                       'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'),
    }
    try:
        response = requests.get(start_url, headers=headers, allow_redirects=True, timeout=10)
        tracker_results["hop_count"] = len(response.history)
        tracker_results["final_url"] = response.url
        for resp in response.history:
            tracker_results["redirect_chain"].append(resp.url)
            ext = tldextract.extract(resp.url)
            if f"{ext.domain}.{ext.suffix}" in KNOWN_SHORTENERS:
                tracker_results["shortener_count"] += 1
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            tracker_results["meta_refresh_found"] = True
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                tracker_results["final_url"] = content.lower().split('url=')[1].strip(' "\'')
    except Exception: pass
    return tracker_results

# ── 4. Main Analytical Engine ─────────────────────────────────────────────────

def analyze_url(url: str, blocklisted: bool = False, allowlisted: bool = False):
    if allowlisted: return {"risk_score": 0, "risk_label": "safe", "checks": [], "resolved_url": url}
    if blocklisted: return {"risk_score": 100, "risk_label": "danger", "checks": [], "resolved_url": url}

    checks = []
    trace_data = trace_redirects(url)
    target_url = trace_data["final_url"]
    total_hops = trace_data["hop_count"]

    # --- PHASE 1: THE UNROLLER ---
    is_nested = trace_data["shortener_count"] >= 2
    checks.append({
        "name": "nested_short", "label": "Nested Shorteners",
        "status": "UNSAFE" if is_nested else "SAFE",
        "message": "Multiple URL shorteners detected in a single chain." if is_nested else "No deceptive shortener nesting. ✓",
        "metric": f"Shorteners: {trace_data['shortener_count']}", "score": 40 if is_nested else 0, "triggered": is_nested
    })

    is_meta_refresh = trace_data["meta_refresh_found"]
    checks.append({
        "name": "html_evasion", "label": "HTML Evasion",
        "status": "UNSAFE" if is_meta_refresh else "SAFE",
        "message": "Hidden HTML redirect detected on landing page." if is_meta_refresh else "No hidden HTML redirects. ✓",
        "metric": "", "score": 30 if is_meta_refresh else 0, "triggered": is_meta_refresh
    })

    # --- PHASE 2: THE ANATOMY ANALYSIS ---
    ext = tldextract.extract(target_url)
    sld, tld = ext.domain, ext.suffix
    subdomain = ext.subdomain
    full_host = f"{subdomain}.{sld}.{tld}".strip('.')
    
    parsed = urlparse(target_url if target_url.startswith("http") else "https://" + target_url)
    scheme = parsed.scheme.lower()

    # 1. IP Address Literal
    is_ip = False
    try:
        ipaddress.ip_address(sld)
        is_ip = True
    except ValueError: pass
    checks.append({
        "name": "ip_literal", "label": "IP Address Literal", "status": "UNSAFE" if is_ip else "SAFE",
        "message": "Link uses a raw IP address instead of a domain name." if is_ip else "Proper domain name used. ✓",
        "metric": f"Host: {sld}" if is_ip else "", "score": W_IP_LITERAL if is_ip else 0, "triggered": is_ip
    })

    # 2. Punycode Attack
    is_puny = "xn--" in full_host or re.search(r'[\u0400-\u04FF]', full_host)
    checks.append({
        "name": "punycode", "label": "Punycode Attack", "status": "UNSAFE" if is_puny else "SAFE",
        "message": "Hidden IDN/Homograph encoding detected." if is_puny else "No Punycode IDN encoding detected. ✓",
        "metric": "", "score": W_PUNYCODE if is_puny else 0, "triggered": is_puny
    })

    # 3. DGA Entropy
    entropy = calculate_entropy(sld)
    is_dga = entropy > 3.65
    checks.append({
        "name": "dga_entropy", "label": "DGA Entropy Analysis", "status": "UNSAFE" if is_dga else "SAFE",
        "message": f"Domain '{sld}' shows machine-generated patterns." if is_dga else "Normal domain entropy. ✓",
        "metric": f"{entropy:.2f} bits", "score": W_DGA_ENTROPY if is_dga else 0, "triggered": is_dga
    })

    # 4. Redirect Chain Depth
    is_deep_redir = total_hops >= 3
    checks.append({
        "name": "redirect_depth", "label": "Redirect Chain Depth", "status": "UNSAFE" if is_deep_redir else "SAFE",
        "message": "Deep redirect chain detected." if is_deep_redir else f"{total_hops} hops followed. ✓",
        "metric": f"Hops: {total_hops}", "score": W_REDIRECT_DEPTH if is_deep_redir else 0, "triggered": is_deep_redir
    })

    # 5. Suspicious TLD
    is_bad_tld = tld.lower() in _BAD_TLDS
    checks.append({
        "name": "suspicious_tld", "label": "Suspicious TLD", "status": "UNSAFE" if is_bad_tld else "SAFE",
        "message": f"TLD '.{tld}' has a high abuse history." if is_bad_tld else f"Standard TLD '.{tld}'. ✓",
        "metric": "", "score": W_SUSPICIOUS_TLD if is_bad_tld else 0, "triggered": is_bad_tld
    })

    # 6. Subdomain Depth
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append({
        "name": "subdomain_depth", "label": "Subdomain Depth", "status": "UNSAFE" if is_deep_sub else "SAFE",
        "message": "High subdomain count detected." if is_deep_sub else "Normal domain depth. ✓",
        "metric": f"Labels: {depth + 2}", "score": W_SUBDOMAIN if is_deep_sub else 0, "triggered": is_deep_sub
    })

    # 7. HTTPS Enforcement
    is_not_https = scheme != "https"
    checks.append({
        "name": "https_mismatch", "label": "HTTPS Enforcement", "status": "UNSAFE" if is_not_https else "SAFE",
        "message": "Link uses unencrypted HTTP." if is_not_https else "Link uses HTTPS. ✓",
        "metric": "", "score": W_HTTPS if is_not_https else 0, "triggered": is_not_https
    })

    # 8. Path Keywords
    path_lower = parsed.path.lower()
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in path_lower]
    path_hit = len(matched_kws) >= 1
    checks.append({
        "name": "path_keywords", "label": "Path Keywords", "status": "UNSAFE" if path_hit else "SAFE",
        "message": f"Phishing keywords found in path." if path_hit else "No suspicious keywords in path. ✓",
        "metric": "", "score": W_PATH_KEYWORDS if path_hit else 0, "triggered": path_hit
    })

    # 9. SLD Keywords
    sld_lower = sld.lower()
    matched_sld = [kw for kw in _SUSPICIOUS_SLD_KEYWORDS if kw in sld_lower]
    sld_hit = len(matched_sld) >= 1
    checks.append({
        "name": "sld_keywords", "label": "Suspicious Domain Name", "status": "UNSAFE" if sld_hit else "SAFE",
        "message": f"Domain contains suspicious keyword(s): {', '.join(matched_sld[:3])}." if sld_hit else "No brand impersonation patterns. ✓",
        "metric": "", "score": W_SLD_KEYWORDS if sld_hit else 0, "triggered": sld_hit
    })

    # ── Addition 3: Check 10: URL Shortener Detection ────────────────────────────
    etld1 = f"{sld}.{tld}".lower()
    hostname = full_host.lower()
    hop_count = total_hops
    
    short_hit = etld1 in _URL_SHORTENERS or hostname in _URL_SHORTENERS
    short_hit = short_hit and hop_count == 0
    
    checks.append({
        "name": "url_shortener",
        "label": "URL Shortener (Hidden Destination)",
        "status": "UNSAFE" if short_hit else "SAFE",
        "triggered": short_hit,
        "score": W_URL_SHORTENER if short_hit else 0,
        "message": (
            f"This QR code uses the URL shortener '{etld1}' to hide the final destination. "
            "URL shorteners in QR codes are a primary quishing technique — the victim cannot "
            "inspect where the link leads without scanning it. The resolver could not follow "
            "this redirect to reveal the true destination."
        ) if short_hit else (
            "No URL shortener detected — destination is directly visible. ✓"
            if etld1 not in _URL_SHORTENERS
            else "URL shortener detected but redirect was followed successfully — final destination scored. ✓"
        ),
        "metric": f"Shortener: {etld1}" if short_hit else ""
    })

    # ── Composite score ──────────────────────────────────────────────────────────
    total_risk = sum(c['score'] for c in checks)
    for c in checks:
        if c['triggered'] and c['name'] in _CRITICAL_OVERRIDE_FLOORS:
            total_risk = max(total_risk, _CRITICAL_OVERRIDE_FLOORS[c['name']])
            
    risk_score = min(100, total_risk)
    risk_label = "safe" if risk_score < 30 else "warning" if risk_score < 65 else "danger"

    return {
        "url": url, "resolved_url": target_url, "risk_score": risk_score,
        "risk_label": risk_label, "checks": checks, "redirect_chain": trace_data["redirect_chain"],
        "hop_count": total_hops, "overall_assessment": f"The URL is {risk_label.upper()}."
    }
