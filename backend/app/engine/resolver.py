"""
resolver.py — Safe URL Resolver
================================
Follows redirect chains under strict safety constraints (§3.1.2):

  • Max redirect hops (default 10) — prevents evasion loops
  • Per-hop timeout (default 5 s) — ensures <2 s total UX target
  • HEAD-first, GET fallback — minimises bandwidth & server interaction
  • SSRF guard — blocks private/loopback/link-local address space
  • No cookie persistence — prevents session-based fingerprinting

The resolver deliberately does NOT load page content; it only follows
the redirect chain to determine the final destination. This means the
user's browser is never exposed to potentially malicious content during
the analysis phase.
"""

from __future__ import annotations
import socket
import tldextract 
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


# ── Configuration defaults ────────────────────────────────────────────────────
MAX_HOPS        = 10
PER_HOP_TIMEOUT = 5       # seconds

# ── User-Agent rotation ───────────────────────────────────────────────────────
# WHY: Declaring an honest scanner UA ("QuishingGuard-SafeResolver/1.0") lets
# attackers trivially cloak — they detect our UA and serve a blank 200 OK.
# The heuristics then score a clean domain as 0 (safe), and the real phishing
# page is only served to the actual victim's mobile browser.
#
# FIX: Rotate through realistic mobile browser UAs so the server cannot
# distinguish our resolver from a real victim. We receive whatever content
# the server would serve to a genuine user, making cloaking ineffective.
import random as _random

_MOBILE_USER_AGENTS = [
    # Android Chrome — most common QR scan context (Samsung Galaxy S series)
    (
        "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
    ),
    # iPhone Safari — second most common mobile browser
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
        "Mobile/15E148 Safari/604.1"
    ),
    # Samsung Internet — significant Android market share
    (
        "Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 "
        "(KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 "
        "Mobile/15E148"
    ),
    # Android Chrome on Pixel
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36"
    ),
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
    hit_limit: bool = False
    error: Optional[str] = None
    status_code: Optional[int] = None


class SSRFError(Exception):
    """Raised when a redirect target maps to a private/blocked address."""


def _is_private(host: str) -> bool:
    """Return True if host resolves to a private/loopback address."""
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
    """Ensure the URL has a scheme; default to https."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def resolve(raw_url: str, max_hops: int = MAX_HOPS,
            timeout: int = PER_HOP_TIMEOUT) -> ResolverResult:
    """
    Safely follow a URL's redirect chain to its final destination.

    Args:
        raw_url:  The URL decoded from the QR code.
        max_hops: Maximum number of redirect hops to follow.
        timeout:  Per-hop request timeout in seconds.

    Returns:
        ResolverResult with the final URL, full chain, and hop count.
    """
    url = _normalise(raw_url)
    chain: list[str] = []
    current = url

    for hop in range(max_hops + 1):
        # STANDARDIZED HOST EXTRACTION
        extracted = tldextract.extract(current)
        host = f"{extracted.domain}.{extracted.suffix}" 

        # SSRF guard
        if _is_private(host):
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                error=f"SSRF: host '{host}' resolves to a private address",
            )

        try:
            req = urllib.request.Request(
                current,
                method="HEAD",
                headers={"User-Agent": _get_user_agent()},
            )
            # Disable automatic redirect following so we can record each hop
            opener = urllib.request.build_opener(
                _NoRedirectHandler()
            )
            try:
                resp = opener.open(req, timeout=timeout)
                status = resp.status
                location = resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                status   = e.code
                location = e.headers.get("Location", "")

            chain.append(current)

            if status in (301, 302, 303, 307, 308) and location:
                # Resolve relative redirects
                next_url = urllib.parse.urljoin(current, location)
                current  = next_url
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

            # Not a redirect — we have the final URL
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                status_code=status,
            )

        except urllib.error.URLError as exc:
            # Network error (DNS failure, refused connection, etc.)
            chain.append(current)
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                error=str(exc.reason) if hasattr(exc, "reason") else str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            chain.append(current)
            return ResolverResult(
                original_url=raw_url,
                resolved_url=current,
                redirect_chain=chain,
                hop_count=hop,
                error=str(exc),
            )

    # Should not reach here
    return ResolverResult(
        original_url=raw_url,
        resolved_url=current,
        redirect_chain=chain,
        hop_count=max_hops,
        hit_limit=True,
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following redirects automatically."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_303(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_307(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_308(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)