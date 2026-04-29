"""
routes/auth.py — POST /api/v1/auth/login (v2.7.3)
==================================================
Issues a signed JWT to administrators.
Rate-limited to 5 attempts/minute per IP to prevent brute-force attacks.

Fixes applied (Batch 2):
  RTE-05  url_prefix removed from Blueprint() constructor. The prefix is
          supplied exclusively by register_blueprint() in __init__.py.
          Having it in both places is a maintenance trap: if the
          register_blueprint() prefix is removed, the route silently
          degrades to /login (no prefix) rather than raising an error.
  RTE-18  get_real_client_ip() used for all log calls instead of
          request.remote_addr. Behind Render's load balancer, remote_addr
          is always the proxy IP — failed login attempts would be logged
          against the wrong address, making brute-force investigation
          impossible.

Request:
  POST /api/v1/auth/login
  Content-Type: application/json
  { "username": "admin", "password": "..." }

Success 200:
  { "token": "<jwt>", "expires_in": 86400, "token_type": "Bearer" }

Failure 401:
  { "error": "Invalid credentials" }
"""
from __future__ import annotations
import hmac
from flask import Blueprint, request, jsonify, current_app

from ..limiter    import limiter, get_real_client_ip  # AUDIT FIX [RTE-18]
from ..utils.auth import create_token
from ..logger     import get_logger

# AUDIT FIX [RTE-05]: url_prefix removed from constructor — single source of
# truth is the register_blueprint() call in app/__init__.py.
bp  = Blueprint("auth", __name__)
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

    # AUDIT FIX [RTE-18]: Use proxy-safe IP for all log records so that
    # failed login attempts are attributed to the real client, not the LB.
    client_ip = get_real_client_ip()

    if not (user_ok and pass_ok):
        log.warning(
            "Failed admin login attempt",
            extra={"ip": client_ip, "username": username},  # RTE-18
        )
        return jsonify({"error": "Invalid credentials"}), 401

    token, expires_in = create_token()
    log.info("Admin login successful", extra={"ip": client_ip})  # RTE-18

    return jsonify({
        "token":      token,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }), 200
