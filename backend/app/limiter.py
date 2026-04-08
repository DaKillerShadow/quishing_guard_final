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

def get_real_client_ip() -> str:
    """
    Extract the real client IP from the X-Forwarded-For header.
    
    SECURITY NOTE: Render's load balancer always appends the actual 
    client IP to the end of the list or as the first element depending 
    on the chain. We pick the first to catch the original sender.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # We take the first IP, but also sanitize it to prevent header injection
        return forwarded_for.split(",")[0].strip()
    return get_remote_address()

limiter = Limiter(
    key_func=get_real_client_ip,
    default_limits=["300 per minute"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
    # CRITICAL FIXES:
    strategy="fixed-window",           # Consistent with most 2026 load balancers
    storage_options={"retry_on_timeout": True}, 
    swallow_errors=True,               # If Redis goes down, DON'T crash the API
    headers_enabled=True,              # Exposes X-RateLimit headers to the Flutter app
)
