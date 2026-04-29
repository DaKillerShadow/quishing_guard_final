"""
app/__init__.py — Flask Application Factory (v2.7.3)
=====================================================
Wires together SQLAlchemy, Flask-Limiter, structured logging, 
JWT config, and blueprints.

Fixes applied (Batch 2):
  RTE-13  Weak default SECRET_KEY now raises RuntimeError in non-test mode
          instead of silently starting. A leaked "dev-change-in-production"
          secret compromises all JWT signatures and session integrity.
          ADMIN_PASSWORD check elevated from warnings.warn() to log.critical()
          so it appears in structured JSON logs on cloud deployments (where
          Python warnings may be silently suppressed).

Pre-existing fixes retained:
  F-03  CORS empty-string bug fixed.
        `"".split(",")` produced `[""]` — Flask-CORS received one empty-string
        origin, which can behave unpredictably. Fix: filter out blank tokens.
        Empty env var → truly empty list → CORS denies all origins.
  F-05  Per-worker rate-limit caveat documented and warned.
        Without REDIS_URL, Flask-Limiter uses in-memory storage. A startup
        warning is emitted when running in non-development mode without Redis.
  F-07  CSP style-src 'unsafe-inline' removed.
        Replaced with `style-src 'none'` which is the correct value for an 
        API JSON server.
"""
from __future__ import annotations
import os
import logging
from flask import Flask, jsonify

from flask_cors import CORS
from .database import db
from .limiter  import limiter
from .logger   import get_logger
from dotenv import load_dotenv
load_dotenv()

log = get_logger("factory")

_WEAK_SECRET_KEY    = "dev-change-in-production"
_WEAK_ADMIN_PASS    = "change-me"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # ── Configuration ──────────────────────────────────────────────────────
    _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app.config.from_mapping(
        SECRET_KEY         = os.environ.get("SECRET_KEY", _WEAK_SECRET_KEY),
        # Database — SQLite default, set DATABASE_URL for PostgreSQL
        # Render provides DATABASE_URL as "postgres://" but SQLAlchemy requires
        # "postgresql://" — silently replacing this prefix fixes the connection.
        SQLALCHEMY_DATABASE_URI = os.environ.get(
            "DATABASE_URL",
            f"sqlite:///{os.path.join(_base_dir, 'quishing_guard.db')}",
        ).replace("postgres://", "postgresql://", 1),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
        MAX_REDIRECT_HOPS  = int(os.environ.get("MAX_REDIRECT_HOPS", 10)),
        RESOLVER_TIMEOUT   = int(os.environ.get("RESOLVER_TIMEOUT", 5)),
        ENTROPY_THRESHOLD  = float(os.environ.get("ENTROPY_THRESHOLD", 3.5)),
        ADMIN_USERNAME     = os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", _WEAK_ADMIN_PASS),
        JWT_EXPIRY_HOURS   = int(os.environ.get("JWT_EXPIRY_HOURS", 24)),
    )

    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", app.config["SECRET_KEY"])

    if test_config:
        app.config.update(test_config)

    # AUDIT FIX [RTE-13]: Hard-fail on weak SECRET_KEY in non-test deployments.
    # A leaked signing secret compromises all JWT tokens and session cookies.
    # In test mode the caller supplies a test_config, so defaults are expected.
    if not test_config:
        if app.config["SECRET_KEY"] == _WEAK_SECRET_KEY:
            raise RuntimeError(
                "FATAL: SECRET_KEY is set to the insecure default value "
                f"'{_WEAK_SECRET_KEY}'. Set the SECRET_KEY environment variable "
                "to a cryptographically random string (e.g. `openssl rand -hex 32`) "
                "before starting the application."
            )

        # AUDIT FIX [RTE-13]: Elevate ADMIN_PASSWORD warning to log.critical()
        # so it appears in structured JSON logs on cloud platforms where Python
        # warnings.warn() output is often silently suppressed.
        if app.config["ADMIN_PASSWORD"] == _WEAK_ADMIN_PASS:
            log.critical(
                "SECURITY ALERT: ADMIN_PASSWORD is set to the insecure default '%s'. "
                "Set the ADMIN_PASSWORD environment variable before deploying.",
                _WEAK_ADMIN_PASS,
            )

    # ── Initialise extensions ──────────────────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)
    
    # F-05: warn operators in non-dev environments if Redis is absent.
    _warn_if_missing_redis()

    # ── Rate-limit error handler (returns JSON not HTML) ───────────────────
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "error":       "Too many requests — please slow down.",
            "retry_after": str(e.description),
        }), 429

    # ── CORS ───────────────────────────────────────────────────────────────
    # F-03 FIX: filter out blank tokens so an empty CORS_ORIGINS env var
    # produces an empty list (deny all), not [""] (undefined behaviour).
    raw_origins  = os.environ.get("CORS_ORIGINS", "")
    cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()] or []

    if cors_origins:
        CORS(
            app,
            origins=cors_origins,
            supports_credentials=False,
            allow_headers=["Content-Type", "Authorization"],
            methods=["GET", "POST", "OPTIONS", "DELETE"],
        )
        log.info("CORS enabled for origins: %s", cors_origins)
    else:
        log.info("CORS_ORIGINS not set or empty — cross-origin requests denied.")

    # ── Security headers ───────────────────────────────────────────────────
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["Referrer-Policy"]           = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        
        # F-07 FIX: replaced 'unsafe-inline' with 'none' for API JSON server
        response.headers["Content-Security-Policy"]   = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers.pop("Server", None)
        return response

    # ── Register blueprints ────────────────────────────────────────────────
    from .routes.auth       import bp as auth_bp
    from .routes.analyse    import bp as analyse_bp
    from .routes.report     import bp as report_bp
    from .routes.health     import bp as health_bp
    from .routes.admin      import bp as admin_bp
    from .routes.scan_image import bp as scan_image_bp

    app.register_blueprint(auth_bp,       url_prefix="/api/v1/auth")
    app.register_blueprint(analyse_bp,    url_prefix="/api/v1")
    app.register_blueprint(report_bp,     url_prefix="/api/v1")
    app.register_blueprint(health_bp,     url_prefix="/api/v1")
    app.register_blueprint(admin_bp,      url_prefix="/api/v1/admin")
    app.register_blueprint(scan_image_bp, url_prefix="/api/v1")

    log.info("Quishing Guard app created")
    return app


def _warn_if_missing_redis() -> None:
    """
    Emit a startup warning when the rate limiter is using in-memory storage
    in a non-development environment.
    """
    flask_env = os.getenv("FLASK_ENV", "production").lower()
    redis_url = os.getenv("REDIS_URL", "")

    if flask_env != "development" and not redis_url:
        log.warning(
            "[F-05] REDIS_URL is not set. The rate limiter is using "
            "in-memory storage, which is per-worker. With multiple Gunicorn "
            "workers the effective rate limit is multiplied by the worker "
            "count. Set REDIS_URL in production to enforce correct limits."
        )
