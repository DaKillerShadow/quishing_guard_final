"""run.py — Entry point for Quishing Guard API v2."""
import os
from app import create_app, db 
from app.logger import get_logger
from app.engine.reputation import seed_database 

app = create_app()
log = get_logger("startup")

# ── HEALTH CHECK ROUTE ──
@app.route('/')
def root_health_check():
    return {
        "status": "Quishing Guard Backend is Live",
        "version": "2.0.0",
        "engine": "Heuristic-8"
    }, 200

# ── 1. DATABASE INITIALIZATION (Runs on Gunicorn Master Boot) ──
try:
    with app.app_context():
        # Redacted log to verify DB type without leaking credentials
        db_type = "PostgreSQL" if "postgresql" in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        log.info(f"🛠️ Initializing {db_type} database...")
        
        # Ensure models are registered to metadata
        try:
            from app.models import db_models 
        except ImportError:
            log.error("❌ CRITICAL: Could not find app.models.db_models!")
        
        db.create_all() 
        
        log.info("🌱 Seeding built-in reputation lists...")
        seed_database()
        log.info("✅ System Ready.")
except Exception as e:
    log.error(f"⚠️ Startup Failure: {e}")

# ── 2. SECURITY AUDIT ──
if os.environ.get("ADMIN_PASSWORD", "change-me") == "change-me":
    log.warning("❌ SECURITY ALERT: Default ADMIN_PASSWORD in use!")

# ── 3. EXECUTION ──
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    log.info(f"🚀 Starting local server on port {port} (Debug: {debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
