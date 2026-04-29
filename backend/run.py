"""
run.py — Entry point for Quishing Guard API v2 (v2.7.3)
========================================================
Fixes applied (Batch 2):
  RTE-09  Removed unused `analyse_url` import. Importing scorer.py at startup
          created the ThreadPoolExecutor, tldextract state, and logging
          handlers outside the app context — unnecessary side effects for
          a symbol that was never called in this module.
  RTE-12  All f-string log calls replaced with %-style formatting. f-strings
          evaluate immediately even when the log level is suppressed, and they
          prevent the JSON formatter from capturing structured fields. The
          logging module's lazy evaluation only works with %-style args.
"""
import os
from app import create_app
from app.database import db
from app.logger import get_logger
from app.engine.reputation import seed_database
from dotenv import load_dotenv
load_dotenv()

app = create_app()
log = get_logger("startup")

# ── HEALTH CHECK ROUTE ──
@app.route('/')
def root_health_check():
    return {"status": "Quishing Guard Backend is Live"}, 200

# ── 1. DATABASE INITIALIZATION (Runs on Render/Gunicorn boot) ──
# Crucial for your project: ensures 'apple.com' and 'aou.edu.eg' are in the DB.
try:
    with app.app_context():
        log.info("🛠️ Checking database tables...")
        
        # 🚨 IMPORTANT: Import models here so SQLAlchemy knows they exist before creating tables
        # Adjust 'app.models.db_models' if your models file is named differently
        try:
            from app.models import db_models 
        except ImportError:
            log.warning("⚠️ Could not import app.models.db_models. Ensure the path is correct.")
        
        db.create_all()  # 👈 THIS ENSURES TABLES EXIST BEFORE SEEDING
        
        log.info("🌱 Seeding database with built-in reputation lists...")
        seed_database()
        log.info("✅ Database seeded successfully.")
except Exception as e:
    # AUDIT FIX [RTE-12]: %-style formatting — not f-string — for lazy eval.
    log.error("⚠️ Database seed failed: %s", e)

# ── 2. SECURITY WARNINGS (Runs on Render/Gunicorn boot) ──
# Note: __init__.py raises RuntimeError on weak SECRET_KEY before we get here.
# This check covers the ADMIN_PASSWORD as a belt-and-suspenders fallback.
if os.environ.get("ADMIN_PASSWORD", "change-me") == "change-me":
    log.critical("❌ SECURITY ALERT: ADMIN_PASSWORD is set to default 'change-me'. "
                 "Please set a secure ADMIN_PASSWORD in your Render environment variables.")

# ── 3. LOCAL DEVELOPMENT EXECUTION (Ignored by Render) ──
if __name__ == "__main__":
    # Robust port parsing to avoid ValueErrors if PORT is empty or malformed
    port_env = os.environ.get("PORT", "5000")
    port = int(port_env) if port_env.isdigit() else 5000
    
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    # AUDIT FIX [RTE-12]: %-style formatting.
    log.info("🚀 Starting Quishing Guard API v2 locally on port %d", port)
    log.info("🛠️ Debug mode: %s", debug)
    
    app.run(host="0.0.0.0", port=port, debug=debug)
