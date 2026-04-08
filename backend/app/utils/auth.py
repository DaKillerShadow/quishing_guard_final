"""
app/utils/auth.py — JWT helpers + admin_required decorator
============================================================
Token lifecycle:
  1. Admin calls POST /api/v1/auth/login with username + password
  2. Server returns a signed JWT (HS256, expires in JWT_EXPIRY_HOURS)
  3. Admin sends:  Authorization: Bearer <token>  on protected endpoints
  4. @admin_required decorator verifies the token on each request

Token payload:
  { "sub": "admin", "iat": <unix>, "exp": <unix> }
"""
from __future__ import annotations
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, current_app


def create_token() -> tuple[str, int]:
    """Issue a new admin JWT. Returns (token_string, expiry_seconds)."""
    expiry_hours = int(current_app.config.get("JWT_EXPIRY_HOURS", 24))
    expiry_secs  = expiry_hours * 3600
    payload = {
        "sub": "admin",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=expiry_secs),
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    return token, expiry_secs


def _extract_token() -> str | None:
    """Pull the Bearer token from the Authorization header."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def verify_token(token: str) -> dict | None:
    """Decode and verify a JWT. Returns the payload dict or None."""
    try:
        return jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def admin_required(f):
    """
    Route decorator — rejects requests without a valid admin JWT.

    Returns 401 if the token is missing or invalid.
    Returns 403 if the token is expired.

    Usage:
        @bp.route("/admin/approve", methods=["POST"])
        @admin_required
        def approve_entry():
            ...
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authorization token required"}), 401

        try:
            jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired — please log in again"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return wrapper
