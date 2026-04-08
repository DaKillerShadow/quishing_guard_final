"""
run.py — Master Entry Point for Quishing Guard API (v2.1.0)
==========================================================
Coordinates the initialization of three critical systems:
1. SQLAlchemy Database (SQLite/Postgres)
2. Local Reputation Seeds (Hardcoded lists)
3. Global Trust Tier (Tranco Top 100k memory-set)
"""

import os
from app import create_app, db 
from app.logger import get_logger
from app.engine.reputation import seed_database, load_reputation_data

app = create_app()
log = get_logger("startup")

# ── 1. HEALTH CHECK ROUTE ──
@app.route('/')
def root_health_check():
    return {
        "status": "Quishing Guard Backend is Live",
        "version": "2.1.0",
        "engine": "Heuristic-8 + Tranco-Trust"
    }, 200

# ── 2. SYSTEM INITIALIZATION ──
# This runs once on Gunicorn Master boot to ensure the environment is ready.
try:
    with app.app_context():
        # A. Database Schema
        db_type = "PostgreSQL" if "postgresql" in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        log.info(f"🛠️ Initializing {db_type} database...")
        
        # Ensure models are registered
        try:
            from app.models import db_models 
        except ImportError:
            log.error("❌ CRITICAL: Could not find app.models.db_models!")
        
        db.create_all() 
        
        # B. Local Seeding
        log.info("🌱 Seeding built-in reputation lists...")
        seed_database()
        
        # C. Global Reputation Tier (Tranco 100k)
        log.info("🌍 Loading Global Trust Tier (Tranco 100k)...")
        load_reputation_data()
        
        log.info("✅ System Ready.")
except Exception as e:
    log.error(f"⚠️ Startup Failure: {e}")

# ── 3. SECURITY AUDIT ──
if os.environ.get("ADMIN_PASSWORD", "change-me") == "change-me":
    log.warning("❌ SECURITY ALERT: Default ADMIN_PASSWORD in use!")

# ── 4. EXECUTION (Local Dev Only) ──
# Gunicorn uses the 'app' object above directly.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    log.info(f"🚀 Starting local server on port {port} (Debug: {debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
