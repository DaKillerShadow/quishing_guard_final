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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
    headers_enabled=True,       # X-RateLimit-* response headers
    retry_after="delta-seconds",
)
