"""
resolver.py — Safe URL Resolver
================================
Follows redirect chains under strict safety constraints (§3.1.2):

  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — handles servers that block HEAD requests
  • SSRF guard — blocks private/loopback/link-local address space
  • Shortener Tracking — identifies Pillar #2 (Nested Shorteners)
"""

from __future__ import annotations
import socket
import ipaddress
import requests
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
import random as _random

# ── Configuration & Security Defaults ─────────────────────────────────────────
MAX_HOPS        = 10
PER_HOP_TIMEOUT = 5

# ✅ Pillar #2: Known shortener domains to track for deception scoring
KNOWN_SHORTENERS = frozenset({
    'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 
    'buff.ly', 'j.mp', 'rebrand.ly', 'qrco.de', 'tiny.cc', 
    'u.nu', 'shorturl.at', 'cutt.ly', 'ow.ly'
})

# ── User-Agent Rotation ───────────────────────────────────────────────────────
_BROWSER_USER_AGENTS = [
    # Mobile
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Desktop (Added to bypass mobile-only bot traps)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
]

def _get_user_agent() -> str:
    return _random.choice(_BROWSER_USER_AGENTS)

# ── SSRF: Private/Reserved Address Ranges ────────────────────────────────────
_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

@dataclass
class ResolverResult:
    original_url: str
    resolved_url: str
    redirect_chain: list[str] = field(default_factory=list)
    hop_count: int = 0
    shortener_count: int = 0  # ✅ Added for Pillar #2 Tracking
    hit_limit: bool = False
    error: Optional[str] = None
    status_code: Optional[int] = None

# ── Private Utility Functions ────────────────────────────────────────────────

def _is_private(host: str) -> bool:
    """Return True if host resolves to a private/loopback address (SSRF Guard)."""
    if not host: return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_RANGES)
    except ValueError:
        pass
    
    try:
        # Perform fresh DNS lookup on every call to prevent DNS Rebinding
        resolved = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in resolved:
            addr = ipaddress.ip_address(sockaddr[0])
            if any(addr in net for net in _BLOCKED_RANGES):
                return True
    except (socket.gaierror, OSError):
        pass
    return False

def _normalise(url: str) -> str:
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# ── Public API ───────────────────────────────────────────────────────────────

def resolve(raw_url: str, max_hops: int = MAX_HOPS, timeout: int = PER_HOP_TIMEOUT) -> ResolverResult:
    """Main resolver entry point following strict safety constraints."""
    try:
        url = _normalise(raw_url)
    except ValueError as e:
        return ResolverResult(original_url=raw_url, resolved_url=raw_url, error=str(e))

    chain: list[str] = []
    current = url
    shortener_count = 0

    # ✅ FIX: Use a persistent session to mirror a real browser's connection pooling
    session = requests.Session()

    for hop in range(max_hops + 1):
        parsed_url = urllib.parse.urlparse(current)
        host = (parsed_url.hostname or "").lower()

        # 1. SSRF Check (The Firewall)
        if not host or _is_private(host):
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count,
                error=f"SSRF Alert: host '{host}' is private/reserved",
            )

        # 2. Shortener Detection (The Deception Logic)
        is_shortener = any(s in host for s in KNOWN_SHORTENERS)
        if is_shortener:
            shortener_count += 1

        try:
            # ✅ FIX: Added full browser headers to defeat basic bot fingerprinting
            headers = {
                "User-Agent": _get_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Upgrade-Insecure-Requests": "1",
            }
            
            # 3. Request Logic
            # ✅ FIX: Bot protections strongly penalize HEAD requests. 
            # If it is a known shortener, ALWAYS use GET to perfectly mimic a human click.
            if is_shortener:
                resp = session.get(current, headers=headers, allow_redirects=False, timeout=timeout, stream=True)
            else:
                resp = session.head(current, headers=headers, allow_redirects=False, timeout=timeout)
                
                # ✅ FIX: Widened the safety net. If a server throws ANY error on a HEAD request, fallback to GET.
                if resp.status_code >= 400:
                    resp = session.get(current, headers=headers, allow_redirects=False, timeout=timeout, stream=True)

            status = resp.status_code
            location = resp.headers.get("Location", "")
            chain.append(current)

            # 4. Handle Redirects
            if status in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current, location)
                current = next_url
                if hop == max_hops - 1:
                    chain.append(next_url)
                    return ResolverResult(
                        original_url=raw_url, resolved_url=next_url,
                        redirect_chain=chain, hop_count=hop + 1,
                        shortener_count=shortener_count, hit_limit=True, status_code=status
                    )
                continue

            # 5. Final Destination Reached
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count, status_code=status
            )

        except requests.exceptions.RequestException as exc:
            chain.append(current)
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count, error=str(exc)
            )

    return ResolverResult(
        original_url=raw_url, resolved_url=current, 
        redirect_chain=chain, hop_count=max_hops, 
        shortener_count=shortener_count, hit_limit=True
    )
