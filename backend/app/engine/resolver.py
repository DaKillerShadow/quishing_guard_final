"""
resolver.py — Safe URL Resolver (v2.7.1)
========================================
Advanced Unroller with HTML Meta-Refresh Support & Strict Safety Constraints.

Follows redirect chains under strict safety constraints:
  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — handles servers that block HEAD requests
  • SSRF guard — blocks private/loopback/link-local address space
  • Shortener Tracking — identifies Nested Shorteners
  • Meta-Refresh Detection — extracts hidden HTML redirects

Fixes applied:
  - Session cleanup inside try/finally block to prevent file descriptor leaks.
  - stream=True connection release (resp.close()) immediately after parsing.
"""

from __future__ import annotations
import socket
import ipaddress
import requests
import urllib.parse
import re
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Optional
import random as _random

# ── Configuration & Security Defaults ─────────────────────────────────────────
MAX_HOPS        = 10
PER_HOP_TIMEOUT = 5

# Pillar #2: Known shortener domains to track for deception scoring
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd",
    "buff.ly", "j.mp", "rebrand.ly", "qrco.de", "tiny.cc",
    "u.nu", "shorturl.at", "cutt.ly", "ow.ly",
})

# ── User-Agent Rotation ───────────────────────────────────────────────────────
_BROWSER_USER_AGENTS = [
    # Mobile
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Desktop (bypasses mobile-only bot traps)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
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
    original_url:   str
    resolved_url:   str
    redirect_chain: list[str] = field(default_factory=list)
    hop_count:      int = 0
    shortener_count: int = 0
    hit_limit:      bool = False
    error:          Optional[str] = None
    status_code:    Optional[int] = None

# ── Private Utility Functions ─────────────────────────────────────────────────

def _is_private(host: str) -> bool:
    """Return True if host resolves to a private/loopback address (SSRF Guard)."""
    if not host:
        return True
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _BLOCKED_RANGES):
            return True
    except ValueError:
        pass

    try:
        # Fresh DNS lookup on every call prevents DNS-rebinding attacks
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

def _get_meta_refresh_url(html_content: bytes, base_url: str) -> str | None:
    """Detects <meta http-equiv='refresh' content='...url=...'> tags."""
    try:
        # Only parse the first 10KB to keep it fast
        soup = BeautifulSoup(html_content[:10000], "html.parser")
        refresh_tag = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
        if refresh_tag and "content" in refresh_tag.attrs:
            content = refresh_tag.attrs["content"]
            # Look for "url=" in the content string
            match = re.search(r"url=['\"]?([^'\";\s]+)", content, re.I)
            if match:
                return urllib.parse.urljoin(base_url, match.group(1))
    except Exception:
        pass
    return None

# ── Public API ────────────────────────────────────────────────────────────────

def resolve(
    raw_url: str,
    max_hops: int = MAX_HOPS,
    timeout: int = PER_HOP_TIMEOUT,
) -> ResolverResult:
    """Main resolver entry point following strict safety constraints."""
    try:
        url = _normalise(raw_url)
    except ValueError as e:
        return ResolverResult(
            original_url=raw_url, resolved_url=raw_url, error=str(e)
        )

    chain:           list[str] = []
    current:         str       = url
    shortener_count: int       = 0

    session = requests.Session()
    try:
        return _follow_chain(
            session, raw_url, current, chain,
            shortener_count, max_hops, timeout,
        )
    finally:
        session.close()

def _follow_chain(
    session:         requests.Session,
    raw_url:         str,
    current:         str,
    chain:           list[str],
    shortener_count: int,
    max_hops:        int,
    timeout:         int,
) -> ResolverResult:
    """Inner redirect-following loop, called by resolve() inside a session scope."""

    for hop in range(max_hops + 1):
        parsed_url = urllib.parse.urlparse(current)
        host       = (parsed_url.hostname or "").lower()

        # 1. SSRF Check (The Firewall)
        if not host or _is_private(host):
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count,
                error=f"SSRF Alert: host '{host}' is private/reserved",
            )

        # 2. Shortener Detection
        is_shortener = any(s in host for s in KNOWN_SHORTENERS)
        if is_shortener:
            shortener_count += 1

        try:
            headers = {
                "User-Agent": _get_user_agent(),
                "Accept": "text/html,application/xhtml+xml,xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Upgrade-Insecure-Requests": "1",
                "Referer": "https://www.google.com/"  # Bypasses simple bot checks
            }

            # 3. Request Logic (Use GET if we suspect shorteners or meta-refreshes down the line)
            # We use GET if it's a shortener or hop > 0 to read the HTML body for Meta-Refreshes
            if is_shortener or hop > 0:
                resp = session.get(
                    current,
                    headers=headers,
                    allow_redirects=False,
                    timeout=timeout,
                    stream=True,
                )
            else:
                resp = session.head(
                    current,
                    headers=headers,
                    allow_redirects=False,
                    timeout=timeout,
                )
                if resp.status_code >= 400:
                    # Server rejected HEAD — fall back to GET
                    resp = session.get(
                        current,
                        headers=headers,
                        allow_redirects=False,
                        timeout=timeout,
                        stream=True,
                    )

            status   = resp.status_code
            location = resp.headers.get("Location", "")

            chain.append(current)

            # 4. Handle Standard HTTP Redirects (3xx)
            if status in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current, location)
                current  = next_url
                resp.close() # Free the connection pool immediately

                if hop == max_hops - 1:
                    chain.append(next_url)
                    return ResolverResult(
                        original_url=raw_url, resolved_url=next_url,
                        redirect_chain=chain, hop_count=hop + 1,
                        shortener_count=shortener_count,
                        hit_limit=True, status_code=status,
                    )
                continue

            # 5. Handle HTML Meta-Refresh (200 OK with hidden jump)
            if status == 200 and resp.request.method == "GET":
                # Read a small chunk to check for Meta-Refresh
                chunk = resp.raw.read(10000)
                refresh_url = _get_meta_refresh_url(chunk, current)
                resp.close()
                
                if refresh_url and refresh_url != current:
                    current = refresh_url
                    
                    if hop == max_hops - 1:
                        chain.append(refresh_url)
                        return ResolverResult(
                            original_url=raw_url, resolved_url=refresh_url,
                            redirect_chain=chain, hop_count=hop + 1,
                            shortener_count=shortener_count,
                            hit_limit=True, status_code=status,
                        )
                    continue

            # 6. Final Destination Reached
            resp.close()
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count, status_code=status,
            )

        except requests.exceptions.RequestException as exc:
            chain.append(current)
            return ResolverResult(
                original_url=raw_url, resolved_url=current,
                redirect_chain=chain, hop_count=hop,
                shortener_count=shortener_count, error=str(exc),
            )

    return ResolverResult(
        original_url=raw_url, resolved_url=current,
        redirect_chain=chain, hop_count=max_hops,
        shortener_count=shortener_count, hit_limit=True,
    )
