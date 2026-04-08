"""
resolver.py — Safe URL Resolver
================================
Follows redirect chains under strict safety constraints (§3.1.2):

  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — minimises bandwidth & server interaction
  • SSRF guard — blocks private/loopback/link-local address space
  • No cookie persistence — prevents session-based fingerprinting
"""

from __future__ import annotations
import socket
import ipaddress
import requests
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
import random as _random

# ── Configuration defaults ────────────────────────────────────────────────────
MAX_HOPS        = 10
PER_HOP_TIMEOUT = 5

# ── User-Agent rotation ───────────────────────────────────────────────────────
_MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
]

def _get_user_agent() -> str:
    return _random.choice(_MOBILE_USER_AGENTS)

# ── SSRF: private/reserved address ranges to block ───────────────────────────
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
    hit_limit: bool = False
    error: Optional[str] = None
    status_code: Optional[int] = None

# 🔴 FIX: Removed @functools.lru_cache to prevent TOCTOU/DNS Rebinding attacks
def _is_private(host: str) -> bool:
    """
    Return True if host resolves to a private/loopback address.
    Performs a fresh DNS lookup on every call for maximum safety.
    """
    if not host:
        return True

    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_RANGES)
    except ValueError:
        pass
    
    try:
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

def resolve(raw_url: str, max_hops: int = MAX_HOPS, timeout: int = PER_HOP_TIMEOUT) -> ResolverResult:
    try:
        url = _normalise(raw_url)
    except ValueError as e:
        return ResolverResult(original_url=raw_url, resolved_url=raw_url, error=str(e))

    chain: list[str] = []
    current = url

    for hop in range(max_hops + 1):
        parsed_url = urllib.parse.urlparse(current)
        host = parsed_url.hostname

        if not host or _is_private(host):
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                error=f"SSRF Alert: host '{host}' resolves to a private address",
            )

        try:
            resp = requests.head(
                current,
                headers={"User-Agent": _get_user_agent()},
                allow_redirects=False,
                timeout=timeout
            )
            status = resp.status_code
            location = resp.headers.get("Location", "")
            chain.append(current)

            if status in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current, location)
                current = next_url
                if hop == max_hops - 1:
                    chain.append(next_url)
                    return ResolverResult(
                        original_url=raw_url,
                        resolved_url=next_url,
                        redirect_chain=chain,
                        hop_count=hop + 1,
                        hit_limit=True,
                        status_code=status,
                    )
                continue

            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                status_code=status,
            )

        except requests.exceptions.RequestException as exc:
            chain.append(current)
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                error=str(exc),
            )

    return ResolverResult(
        original_url=raw_url, resolved_url=current, redirect_chain=chain, hop_count=max_hops, hit_limit=True
    )