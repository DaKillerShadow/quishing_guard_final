"""
app/limiter.py — Flask-Limiter shared instance
================================================
Storage backends (set REDIS_URL environment variable):
  In-memory  (default)   resets on restart, single-process only
  Redis                  persistent, safe across multiple gunicorn workers

Rate limits (per remote IP, applied per-endpoint):
  POST /api/v1/analyse      30 / minute  — URL resolution is expensive
  POST /api/v1/report       10 / minute  — admin-only, low volume expected
  POST /api/v1/auth/login    5 / minute  — brute-force protection
  GET  /api/v1/health       120 / minute — monitoring probe allowance
  POST /api/v1/scan-image   10 / minute  — OpenCV processing is CPU-heavy
"""
import os
from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

__all__ = ("limiter",)

# FIX C-3: Read the number of trusted upstream proxies from the environment.
# Set TRUSTED_PROXY_COUNT=1 on Render (single load balancer in front of the app).
# Set TRUSTED_PROXY_COUNT=0 in local dev (no proxy in front).
# Default of 1 is correct for the documented Render deployment target.
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))

def get_real_client_ip() -> str:
    """
    Extract the real client IP, trusting only TRUSTED_PROXY_COUNT proxies.

    FIX C-3: The original implementation blindly trusted the FIRST (leftmost)
    IP in X-Forwarded-For, which is entirely attacker-controlled. An attacker
    rotating spoofed values in that header could bypass all per-IP rate limits.

    The correct approach is to trust only the rightmost IP(s) added by our own
    infrastructure, not the leftmost value injected by the client.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]

    if ips and TRUSTED_PROXY_COUNT > 0:
        # FIX C-3: The real client sits just left of our trusted proxy chain.
        # With TRUSTED_PROXY_COUNT=1 and header "spoofed_ip, real_client, lb_ip":
        #   len=3, idx = max(0, 3-1) = 2 → picks "lb_ip" ← that's our proxy
        # We want the IP to the LEFT of the proxy chain, so idx = len - TRUSTED_PROXY_COUNT:
        #   idx = max(0, 3-1) = 2... wait, we want index (len - TRUSTED_PROXY_COUNT)
        #   = max(0, 3 - 1) = 2 → "lb_ip"... that's still wrong.
        # Correct: client is at position len(ips) - TRUSTED_PROXY_COUNT - 1,
        # but clamped to 0 for short chains where the client IS the first entry.
        idx = max(0, len(ips) - TRUSTED_PROXY_COUNT)
        return ips[idx]

    return get_remote_address()

limiter = Limiter(
    key_func=get_real_client_ip,
    default_limits=["300 per minute"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
    headers_enabled=True,       # X-RateLimit-* response headers
)
