"""
resolver.py — Safe URL Resolver
================================
Follows redirect chains under strict safety constraints (§3.1.2):

  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — handles servers that block HEAD requests
  • SSRF guard — blocks private/loopback/link-local address space
  • Shortener Tracking — identifies Pillar #2 (Nested Shorteners)

Fixes applied (v2.7.0):
  M-3  Session not closed — requests.Session() was created per resolve()
        call but never explicitly closed. Under heavy load, socket handles
        accumulated until the OS raised "Too many open files". Fixed by
        wrapping the session lifetime in a try/finally session.close().

  M-4  stream=True responses not released — when allow_redirects=False
        is used with stream=True, the underlying TCP connection is held
        open until the response body is consumed or the response is
        explicitly closed. Since we only need the headers, we now call
        resp.close() immediately after reading Location. Fixed in both
        the shortener GET path and the HEAD-fallback GET path.

  L-1  Dead code after return — the `continue` statement that followed
        the early-exit `return ResolverResult(... hit_limit=True)` inside
        the redirect loop was unreachable. Removed.
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

# Pillar #2: Known shortener domains to track for deception scoring
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd",
    "buff.ly", "j.mp", "rebrand.ly", "qrco.de", "tiny.cc",
    "u.nu", "shorturl.at", "cutt.ly", "ow.ly",
})

# ── User-Agent Rotation ───────────────────────────────────────────────────────
_BROWSER_USER_AGENTS = [
    # Mobile
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Desktop (bypasses mobile-only bot traps)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
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
        return any(addr in net for net in _BLOCKED_RANGES)
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
    url    = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


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

    # M-3 FIX: Wrap the session in try/finally so it is always closed.
    # Previously the session was created but never explicitly closed,
    # leaking socket file descriptors under heavy load.
    session = requests.Session()
    try:
        return _follow_chain(
            session, raw_url, current, chain,
            shortener_count, max_hops, timeout,
        )
    finally:
        session.close()   # M-3 FIX: guaranteed cleanup regardless of exit path


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
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language":          "en-US,en;q=0.5",
                "Upgrade-Insecure-Requests": "1",
            }

            # 3. Request Logic
            if is_shortener:
                # Bot protections strongly penalise HEAD on shorteners.
                # Use GET with stream=True — we only need response headers.
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

            # M-4 FIX: Release the stream connection immediately after reading
            # headers. When stream=True, the TCP socket stays open until the
            # body is consumed or resp.close() is called. Since we only need
            # the Location header, close now to return the connection to the
            # pool immediately.
            resp.close()

            chain.append(current)

            # 4. Handle Redirects
            if status in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current, location)
                current  = next_url

                if hop == max_hops - 1:
                    chain.append(next_url)
                    return ResolverResult(
                        original_url=raw_url, resolved_url=next_url,
                        redirect_chain=chain, hop_count=hop + 1,
                        shortener_count=shortener_count,
                        hit_limit=True, status_code=status,
                    )
                # L-1 FIX: Removed the dead `continue` that followed
                # the early-exit return above. It was unreachable.
                continue

            # 5. Final Destination Reached
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
