"""
app/__init__.py — Master Integrated Flask Application Factory
==============================================================
Final production version for Quishing Guard v2.0.0 (2026).
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from flask import Flask, jsonify, request

from flask_cors import CORS
from .database import db
from .limiter  import limiter
from .logger   import get_logger

log = get_logger("factory")

def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # ── 1. Root Route for Health & Deployment Info ────────────────────────
    @app.route('/')
    def index():
        return jsonify({
            "project": "Quishing Guard API",
            "version": "2.0.0",
            "status": "operational",
            "author": "Mohamed Abdelfattah",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    # ── 2. Configuration & Security ───────────────────────────────────────
    _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-key-change-in-prod"),
        # Standardize PostgreSQL prefix for Render
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            f"sqlite:///{os.path.join(_base_dir, 'quishing_guard.db')}",
        ).replace("postgres://", "postgresql://", 1),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # Image Security: 16MB Limit for OpenCV QR Scanning
        MAX_CONTENT_LENGTH=16 * 1024 * 1024, 
        CORS_ORIGINS=os.environ.get("CORS_ORIGINS", "*"),
    )

    if test_config:
        app.config.update(test_config)

    # ── 3. Extensions & Request Logging ───────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)
    CORS(app, origins=app.config["CORS_ORIGINS"], supports_credentials=True)

    @app.before_request
    def log_request_info():
        # Audit Trail: Logs method, path, and remote IP
        log.info(f"Inbound: {request.method} {request.path} from {request.remote_addr}")

    # ── 4. Database Setup & Seeding ───────────────────────────────────────
    with app.app_context():
        # Import models to register them with SQLAlchemy metadata
        from .models.db_models import BlocklistEntry, AllowlistEntry, ScanLog  # noqa: F401
        db.create_all()
        # Seed the built-in reputation lists (apple.com, etc.)
        from .engine.reputation import seed_database
        seed_database()
        log.info("Database synchronized and seeded.")

    # ── 5. Standardized JSON Error Handlers ───────────────────────────────
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    @app.errorhandler(413)
    def request_entity_too_large(e):
        # Specifically handles large images for the OpenCV scan-image route
        return jsonify({"error": "Image file too large (Max 16MB allowed)."}), 413

    # ── 6. Security Headers ───────────────────────────────────────────────
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # ── 7. Blueprint Registration with v1 Prefixes ────────────────────────
    from .routes.auth       import bp as auth_bp
    from .routes.analyse    import bp as analyse_bp
    from .routes.report     import bp as report_bp
    from .routes.health     import bp as health_bp
    from .routes.admin      import bp as admin_bp
    from .routes.scan_image import bp as scan_image_bp

    app.register_blueprint(auth_bp,       url_prefix='/api/v1/auth')
    app.register_blueprint(analyse_bp,    url_prefix='/api/v1')
    app.register_blueprint(report_bp,     url_prefix='/api/v1')
    app.register_blueprint(health_bp,     url_prefix='/api/v1')
    app.register_blueprint(admin_bp,      url_prefix='/api/v1/admin')
    app.register_blueprint(scan_image_bp, url_prefix='/api/v1')

    log.info("Quishing Guard system fully initialized.")
    return app