"""
app/__init__.py — Flask Application Factory
=============================================
Wires together:
  - SQLAlchemy  (database)
  - Flask-Limiter (rate limiting)
  - Structured logging
  - JWT config for admin auth
  - All route blueprints

Fixes applied:
  F-03  CORS empty-string bug.
        `"".split(",")` produced `[""]` — Flask-CORS received one empty-string
        origin, which can behave unpredictably.  Fix: filter out blank tokens.
        Empty env var → truly empty list → CORS denies all origins.

  F-05  Per-worker rate-limit caveat documented.
        Without REDIS_URL, Flask-Limiter uses in-memory storage.  With N
        Gunicorn workers the effective limit is N × configured limit.  A
        startup warning is emitted when running in non-development mode without
        Redis so the issue is visible in logs immediately.

  F-07  CSP `style-src 'unsafe-inline'` removed.
        This is a JSON-only API — there is no UI to style.  Replaced with
        `style-src 'none'` which is the correct value for an API server.
"""
from __future__ import annotations
import os
import logging
from flask import Flask, jsonify

from flask_cors import CORS
from .database import db
from .limiter  import limiter
from .logger   import get_logger

log = get_logger("factory")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # ── Configuration ──────────────────────────────────────────────────────
    _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app.config.from_mapping(
        # Core
        SECRET_KEY         = os.environ.get("SECRET_KEY", "dev-change-in-production"),
        # Database — SQLite default, set DATABASE_URL for PostgreSQL
        # Render provides DATABASE_URL as "postgres://" but SQLAlchemy requires
        # "postgresql://" — silently replacing this prefix fixes the connection.
        SQLALCHEMY_DATABASE_URI = os.environ.get(
            "DATABASE_URL",
            f"sqlite:///{os.path.join(_base_dir, 'quishing_guard.db')}",
        ).replace("postgres://", "postgresql://", 1),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
        # Analysis engine
        MAX_REDIRECT_HOPS  = int(os.environ.get("MAX_REDIRECT_HOPS", 10)),
        RESOLVER_TIMEOUT   = int(os.environ.get("RESOLVER_TIMEOUT", 5)),
        ENTROPY_THRESHOLD  = float(os.environ.get("ENTROPY_THRESHOLD", 3.5)),
        # Admin auth
        ADMIN_USERNAME     = os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", "change-me"),
        JWT_EXPIRY_HOURS   = int(os.environ.get("JWT_EXPIRY_HOURS", 24)),
    )

    # F-04 sync: ensure JWT_SECRET maps to SECRET_KEY fallback if unset
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", app.config["SECRET_KEY"])

    if test_config:
        app.config.update(test_config)

    # ── Admin password default guard (audit Section 6) ────────────────────
    # Warn loudly if the insecure default password is still set.
    # This does not block startup, but the warning will appear in server logs.
    if not test_config and app.config["ADMIN_PASSWORD"] == "change-me":
        import warnings
        warnings.warn(
            "ADMIN_PASSWORD is using the insecure default 'change-me'. "
            "Set the ADMIN_PASSWORD environment variable before deploying.",
            stacklevel=2,
        )

    # ── Initialise extensions ──────────────────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)

    # F-05: warn operators in non-dev environments if Redis is absent.
    _warn_if_missing_redis()

    # ── Rate-limit error handler (returns JSON not HTML) ──────────────────
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "error": "Too many requests — please slow down.",
            "retry_after": str(e.description),
        }), 429

    # ── Updated CORS ──────────────────────────────────────────────────────
    # F-03 FIX: filter out blank tokens so an empty CORS_ORIGINS env var
    # produces an empty list (deny all), not [""] (undefined behaviour).
    raw_origins = os.environ.get("CORS_ORIGINS", "")
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
        # Implicitly denies CORS requests by skipping CORS() registration
        log.info("CORS_ORIGINS not set or empty — cross-origin requests denied.")

    # ── Security headers ───────────────────────────────────────────────────
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["Referrer-Policy"]        = "no-referrer"
        
        # Add HSTS — instructs browsers to enforce HTTPS for 2 years.
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        
        # F-07 FIX: replaced 'unsafe-inline' with 'none' for API JSON server
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        # Lock down sensitive browser APIs not needed by this API service.
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Strip Flask's default Server header to avoid version fingerprinting.
        response.headers.pop("Server", None)
        
        return response

    # ── Register blueprints ────────────────────────────────────────────────
    from .routes.auth    import bp as auth_bp
    from .routes.analyse import bp as analyse_bp
    from .routes.report  import bp as report_bp
    from .routes.health  import bp as health_bp
    from .routes.admin   import bp as admin_bp
    from .routes.scan_image import bp as scan_image_bp

    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(analyse_bp, url_prefix='/api/v1')
    app.register_blueprint(report_bp, url_prefix='/api/v1')
    app.register_blueprint(health_bp, url_prefix='/api/v1')
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    app.register_blueprint(scan_image_bp, url_prefix='/api/v1')

    log.info("Quishing Guard app created")
    return app


# ---------------------------------------------------------------------------
# F-05 helper
# ---------------------------------------------------------------------------

def _warn_if_missing_redis() -> None:
    """
    Emit a startup warning when the rate limiter is using in-memory storage
    in a non-development environment.

    WHY THIS MATTERS (F-05):
        With N Gunicorn workers, each worker maintains its own in-memory
        counter.  A 30 req/min limit becomes effectively N × 30 req/min
        (e.g. 120 req/min with 4 workers).  Redis provides a shared counter
        across all workers, restoring the intended limit.

    Production deployment checklist:
        Set the REDIS_URL environment variable, e.g.:
            REDIS_URL=redis://:password@your-redis-host:6379/0
        The limiter.py module reads this variable and switches to
        RedisStorage automatically when it is present.
    """
    flask_env = os.getenv("FLASK_ENV", "production").lower()
    redis_url = os.getenv("REDIS_URL", "")

    if flask_env != "development" and not redis_url:
        log.warning(
            "[F-05] REDIS_URL is not set.  The rate limiter is using "
            "in-memory storage, which is per-worker.  With multiple Gunicorn "
            "workers the effective rate limit is multiplied by the worker "
            "count.  Set REDIS_URL in production to enforce correct limits."
        )

