"""
routes/auth.py — POST /api/v1/auth/login
==========================================
Issues a signed JWT to administrators.

Rate-limited to 5 attempts/minute per IP to prevent brute-force attacks.

Request:
  POST /api/v1/auth/login
  Content-Type: application/json
  { "username": "admin", "password": "..." }

Success 200:
  { "token": "<jwt>", "expires_in": 86400, "token_type": "Bearer" }

Failure 401:
  { "error": "Invalid credentials" }

The token is then used on all admin-only endpoints:
  Authorization: Bearer <token>
"""
from __future__ import annotations
import hmac
from flask import Blueprint, request, jsonify, current_app

from ..limiter     import limiter, get_real_client_ip  # BUG FIX: Imported IP helper
from ..utils.auth  import create_token
from ..logger      import get_logger

bp  = Blueprint("auth", __name__, url_prefix="/api/v1/auth")
log = get_logger("auth")

@bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()

    expected_user = current_app.config.get("ADMIN_USERNAME", "admin")
    expected_pass = current_app.config.get("ADMIN_PASSWORD", "change-me")

    # hmac.compare_digest prevents timing-attack leakage
    user_ok = hmac.compare_digest(username, expected_user)
    pass_ok = hmac.compare_digest(password, expected_pass)

    # Grab the real IP, bypassing cloud proxies
    actual_ip = get_real_client_ip()

    if not (user_ok and pass_ok):
        log.warning("Failed admin login attempt",
                    extra={"ip": actual_ip, "username": username})
        return jsonify({"error": "Invalid credentials"}), 401

    token, expires_in = create_token()
    log.info("Admin login successful", extra={"ip": actual_ip})

    return jsonify({
        "token":      token,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }), 200
