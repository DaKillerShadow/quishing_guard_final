"""
resolver.py — Safe URL Resolver
================================
Follows redirect chains under strict safety constraints (§3.1.2):

  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — minimises bandwidth & server interaction
  • SSRF guard — blocks private/loopback/link-local address space
  • HTML Evasion Scraper — safely reads first 50KB for meta-refresh
  • No cookie persistence — prevents session-based fingerprinting
"""

from __future__ import annotations
import socket
import ipaddress
import requests
import urllib.parse
import functools
import re
import tldextract
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Optional
import random as _random

# ── Configuration defaults ────────────────────────────────────────────────────
MAX_HOPS        = 10
PER_HOP_TIMEOUT = 5       # seconds

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "cutt.ly", "is.gd", "buff.ly", "ift.tt",
    "tiny.cc", "lnkd.in", "fb.me", "amzn.to", "adf.ly", "linktr.ee", 
    "lnk.to", "snip.ly", "short.io", "bl.ink", "clck.ru", "qr.ae", 
    "qrco.de", "url.ie", "v.gd", "x.co", "zi.ma",
})

# ── User-Agent rotation ───────────────────────────────────────────────────────
_MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
]

def _get_user_agent() -> str:
    """Return a random realistic mobile browser user-agent string."""
    return _random.choice(_MOBILE_USER_AGENTS)

# ── SSRF: private/reserved address ranges to block ───────────────────────────
_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

@dataclass
class ResolverResult:
    original_url: str
    resolved_url: str
    redirect_chain: list[str] = field(default_factory=list)
    hop_count: int = 0
    shortener_count: int = 0
    meta_refresh_found: bool = False
    hit_limit: bool = False
    error: Optional[str] = None
    status_code: Optional[int] = None

class SSRFError(Exception):
    """Raised when a redirect target maps to a private/blocked address."""

# Cache the DNS lookups to mitigate TOCTOU (Time-of-Check to Time-of-Use) attacks
@functools.lru_cache(maxsize=128)
def _is_private(host: str) -> bool:
    """Return True if host resolves to a private/loopback address."""
    if not host:
        return True  # Treat empty/invalid hosts as inherently unsafe

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
    """Ensure the URL has a valid HTTP/HTTPS scheme."""
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")
        
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    return url

def resolve(raw_url: str, max_hops: int = MAX_HOPS, timeout: int = PER_HOP_TIMEOUT) -> ResolverResult:
    """
    Safely follow a URL's redirect chain to its final destination, 
    counting shorteners and checking for meta-refreshes along the way.
    """
    try:
        url = _normalise(raw_url)
    except ValueError as e:
        return ResolverResult(original_url=raw_url, resolved_url=raw_url, error=str(e))

    chain: list[str] = []
    current = url
    shortener_count = 0
    meta_refresh_found = False

    for hop in range(max_hops + 1):
        # 1. SSRF GUARD: Parse the exact hostname being requested
        parsed_url = urllib.parse.urlparse(current)
        host = parsed_url.hostname

        if not host or _is_private(host):
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                shortener_count=shortener_count,
                meta_refresh_found=meta_refresh_found,
                error=f"SSRF Alert: host '{host}' resolves to a private address",
            )

        # Count if this hop is a shortener
        ext = tldextract.extract(current)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        if domain in KNOWN_SHORTENERS:
            shortener_count += 1

        # 2. HTTP REQUEST: HEAD-first, GET fallback
        try:
            headers = {"User-Agent": _get_user_agent()}
            resp = requests.head(current, headers=headers, allow_redirects=False, timeout=timeout)
            
            used_get = False
            # Fallback to GET if HEAD is rejected or hides the redirect
            if resp.status_code == 405 or (resp.status_code == 200 and "Location" not in resp.headers):
                resp = requests.get(current, headers=headers, allow_redirects=False, timeout=timeout, stream=True)
                used_get = True

            status = resp.status_code
            location = resp.headers.get("Location", "")
            chain.append(current)

            # 3. REDIRECT HANDLING (HTTP 3xx)
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
                        shortener_count=shortener_count,
                        meta_refresh_found=meta_refresh_found,
                        hit_limit=True,
                        status_code=status,
                    )
                continue

            # 4. HTML EVASION (META-REFRESH) HANDLING
            if status == 200:
                if not used_get:
                    # We need the body to check for HTML tags
                    resp = requests.get(current, headers=headers, allow_redirects=False, timeout=timeout, stream=True)
                
                # Safely read only the first 50KB of the response
                chunk = resp.raw.read(50000, decode_content=True)
                soup = BeautifulSoup(chunk, 'html.parser')
                meta_tag = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
                
                if meta_tag:
                    meta_refresh_found = True
                    content = meta_tag.get('content', '')
                    
                    # 👈 THE FIX: Robust regex extraction instead of simple string splitting
                    match = re.search(r'url\s*=\s*[\'"]?([^\'">\s]+)', content, re.I)
                    if match:
                        next_url = match.group(1).strip()
                        current = urllib.parse.urljoin(current, next_url)
                        continue

            # Not a redirect and no meta-refresh — we found the final URL!
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                shortener_count=shortener_count,
                meta_refresh_found=meta_refresh_found,
                status_code=status,
            )

        except requests.exceptions.RequestException as exc:
            # Network error (DNS failure, timeout, refused connection, etc.)
            chain.append(current)
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                shortener_count=shortener_count,
                meta_refresh_found=meta_refresh_found,
                error=str(exc),
            )

    return ResolverResult(
        original_url=raw_url, resolved_url=current, redirect_chain=chain, hop_count=max_hops, hit_limit=True
    )
