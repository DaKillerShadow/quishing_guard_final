"""
scorer.py — Master Integrated Heuristic Scoring Engine
======================================================
Core analytical engine for Quishing Guard (§2.4, §3.1.1).
Calculates risk scores based on 8 security indicators.
"""

from __future__ import annotations
import math
import re
import ipaddress
import tldextract
from dataclasses import dataclass, field
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

# ── 3. Data Structures (Synchronized with Flutter) ──────────────────────────

@dataclass
class CheckResult:
    name: str           
    label: str          
    status: str         # "SAFE" or "UNSAFE"
    description: str    # Mapped to 'message' in analyse.py for Flutter
    detail: str         # Mapped to 'metric' in analyse.py for Flutter
    score: int          
    triggered: bool     

@dataclass
class ScorerResult:
    raw_url: str
    resolved_url: str
    risk_score: int
    risk_label: str
    top_threat: str
    checks: list[CheckResult] = field(default_factory=list)
    overall_assessment: str = ""
    is_allowlisted: bool = False
    is_blocklisted: bool = False

# ── 4. Analytical Helpers ─────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Implements H(X) = -∑ p(xᵢ) log₂(p(xᵢ)) for DGA detection."""
    if not text: return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

# ── 5. Main Analytical Engine ─────────────────────────────────────────────────

def score(
    resolved_url: str, 
    raw_url: str,
    redirect_chain: list[str],
    hop_count: int = 0, 
    blocklisted: bool = False,
    allowlisted: bool = False
) -> ScorerResult:
    """
    Evaluates the URL and generates a professional Security Analysis Report.
    """
    if allowlisted:
        return ScorerResult(raw_url, resolved_url, 0, "safe", "None", [], "Trusted Domain.", True, False)
    
    if blocklisted:
        return ScorerResult(raw_url, resolved_url, 100, "danger", "Blocklisted", [], "Known Malicious Domain.", False, True)

    # A. Extraction using tldextract for accuracy
    ext = tldextract.extract(resolved_url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_host = f"{subdomain}.{domain}.{suffix}".strip('.')
    
    parsed = urlparse(resolved_url if resolved_url.startswith("http") else "https://" + resolved_url)
    scheme = parsed.scheme.lower()
    
    checks: list[CheckResult] = []

    # ── Check 1: IP Address Literal ──
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError: pass
    
    checks.append(CheckResult(
        name="ip_literal", label="IP Address Literal",
        status="UNSAFE" if is_ip else "SAFE",
        description="Link uses a raw IP address instead of a domain name." if is_ip 
                else "Link uses a proper registered domain name. ✓",
        detail=f"Host: {domain}" if is_ip else "",
        score=W_IP_LITERAL if is_ip else 0, triggered=is_ip
    ))

    # ── Check 2: Punycode / Homograph Attack ──
    is_puny = "xn--" in full_host
    checks.append(CheckResult(
        name="punycode", label="Punycode / Homograph Attack",
        status="UNSAFE" if is_puny else "SAFE",
        description="Punycode IDN encoding detected – potential homograph risk!" if is_puny 
                else "No Punycode IDN encoding detected. ✓",
        detail="", score=W_PUNYCODE if is_puny else 0, triggered=is_puny
    ))

    # ── Check 3: DGA Entropy Analysis ──
    entropy = calculate_entropy(domain)
    is_dga = entropy > 3.55
    checks.append(CheckResult(
        name="dga_entropy", label="DGA Entropy Analysis",
        status="UNSAFE" if is_dga else "SAFE",
        description=f"Domain '{domain}' shows machine-generated patterns." if is_dga 
                else f"Domain entropy is within normal range. ✓",
        detail=f"Entropy: {entropy:.2f} bits",
        score=W_DGA_ENTROPY if is_dga else 0, triggered=is_dga
    ))

    # ── Check 4: Redirect Chain Depth ──
    is_deep_redir = hop_count >= 3
    checks.append(CheckResult(
        name="redirect_depth", label="Redirect Chain Depth",
        status="UNSAFE" if is_deep_redir else "SAFE",
        description="Deep redirect chain detected – potential cloaking attempt." if is_deep_redir 
                else f"{hop_count} redirect hops – within normal range. ✓",
        detail=f"Hops: {hop_count}", score=W_REDIRECT_DEPTH if is_deep_redir else 0, triggered=is_deep_redir
    ))

    # ── Check 5: Suspicious TLD ──
    is_bad_tld = suffix.lower() in _BAD_TLDS
    checks.append(CheckResult(
        name="suspicious_tld", label="Suspicious Top-Level Domain",
        status="UNSAFE" if is_bad_tld else "SAFE",
        description=f"TLD '.{suffix}' has an elevated abuse history." if is_bad_tld 
                else f"TLD '.{suffix}' is a standard extension. ✓",
        detail="", score=W_SUSPICIOUS_TLD if is_bad_tld else 0, triggered=is_bad_tld
    ))

    # ── Check 6: Excessive Subdomain Depth ──
    depth = len(subdomain.split('.')) if subdomain else 0
    is_deep_sub = depth >= 3
    checks.append(CheckResult(
        name="subdomain_depth", label="Excessive Subdomain Depth",
        status="UNSAFE" if is_deep_sub else "SAFE",
        description="High number of subdomains detected – common in phishing." if is_deep_sub 
                else f"Normal domain depth. ✓",
        detail=f"Labels: {depth + 2}", score=W_SUBDOMAIN if is_deep_sub else 0, triggered=is_deep_sub
    ))

    # ── Check 7: HTTPS Enforcement ──
    is_not_https = scheme != "https"
    checks.append(CheckResult(
        name="https_mismatch", label="HTTPS Enforcement",
        status="UNSAFE" if is_not_https else "SAFE",
        description="Link uses unencrypted HTTP protocol." if is_not_https 
                else "Link uses encrypted HTTPS protocol. ✓",
        detail="", score=W_HTTPS if is_not_https else 0, triggered=is_not_https
    ))

    # ── Check 8: Path Keyword Analysis ──
    path_lower = parsed.path.lower()
    matched_kws = [kw for kw in _PHISHING_PATH_KEYWORDS if kw in path_lower]
    path_hit = len(matched_kws) >= 1
    checks.append(CheckResult(
        name="path_keywords", label="Suspicious Path Keywords",
        status="UNSAFE" if path_hit else "SAFE",
        description=f"Phishing keywords ({', '.join(matched_kws)}) found in path." if path_hit 
                else "No suspicious keyword combinations in path. ✓",
        detail="", score=W_PATH_KEYWORDS if path_hit else 0, triggered=path_hit
    ))

    # ── Final Aggregation & Overrides ──
    total_risk = sum(c.score for c in checks)
    
    # Apply critical floors (if a major threat is found, score can't be 'Safe')
    for c in checks:
        if c.triggered and c.name in _CRITICAL_OVERRIDE_FLOORS:
            total_risk = max(total_risk, _CRITICAL_OVERRIDE_FLOORS[c.name])
            
    risk_score = min(100, total_risk)
    
    # Determine the Risk Label
    if risk_score < 30: 
        label = "safe"
    elif risk_score < 65: 
        label = "warning"
    else: 
        label = "danger"

    # Identify Top Threat
    triggered_names = [c.label for c in checks if c.triggered]
    top_threat = triggered_names[0] if triggered_names else "None"

    return ScorerResult(
        raw_url=raw_url,
        resolved_url=resolved_url,
        risk_score=risk_score,
        risk_label=label,
        top_threat=top_threat,
        checks=checks,
        overall_assessment=f"The provided URL appears to be {label.upper()} based on indicators.",
        is_allowlisted=False,
        is_blocklisted=False
    )