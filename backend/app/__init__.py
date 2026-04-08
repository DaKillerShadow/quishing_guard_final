"""
app/__init__.py — Flask Application Factory
=============================================
Wires together:
  - SQLAlchemy  (database)
  - Flask-Limiter (rate limiting)
  - Structured logging
  - JWT config for admin auth
  - All route blueprints
"""
from __future__ import annotations
import os
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
        CORS_ORIGINS       = os.environ.get("CORS_ORIGINS", "*"),
        # Admin auth
        ADMIN_USERNAME     = os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", "change-me"),
        JWT_EXPIRY_HOURS   = int(os.environ.get("JWT_EXPIRY_HOURS", 24)),
    )

    if test_config:
        app.config.update(test_config)

    # ── Initialise extensions ──────────────────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)

    # 🚨 DB INIT REMOVED: 
    # db.create_all() and seed_database() have been safely moved to run.py
    # to prevent Gunicorn worker race conditions and database locks.

    # ── Rate-limit error handler (returns JSON not HTML) ──────────────────
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "error": "Too many requests — please slow down.",
            "retry_after": str(e.description),
        }), 429

    # ── Updated CORS ──────────────────────────────────────────────────────
    raw_origins = app.config["CORS_ORIGINS"]
    cors_origins = [o.strip() for o in raw_origins.split(",")] if raw_origins != "*" else "*"
    
    CORS(
        app,
        origins=cors_origins,
        supports_credentials=False, 
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "OPTIONS", "DELETE"],
    )

    # ── Security headers ───────────────────────────────────────────────────
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["Referrer-Policy"]        = "no-referrer"
        return response

    # ── Register blueprints ────────────────────────────────────────────────
    from .routes.auth    import bp as auth_bp
    from .routes.analyse import bp as analyse_bp
    from .routes.report  import bp as report_bp
    from .routes.health  import bp as health_bp
    from .routes.admin   import bp as admin_bp
    from .routes.scan_image import bp as scan_image_bp

    # FIXED: Added the /api/v1 prefix to correctly map the endpoints
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(analyse_bp, url_prefix='/api/v1')
    app.register_blueprint(report_bp, url_prefix='/api/v1')
    app.register_blueprint(health_bp, url_prefix='/api/v1')
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    app.register_blueprint(scan_image_bp, url_prefix='/api/v1')

    log.info("Quishing Guard app created")
    return app
    from .routes.admin   import bp as admin_bp
    from .routes.scan_image import bp as scan_image_bp

    # FIXED: Added the /api/v1 prefix to correctly map the endpoints
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(analyse_bp, url_prefix='/api/v1')
    app.register_blueprint(report_bp, url_prefix='/api/v1')
    app.register_blueprint(health_bp, url_prefix='/api/v1')
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    app.register_blueprint(scan_image_bp, url_prefix='/api/v1')

    log.info("Quishing Guard app created")
    return app
