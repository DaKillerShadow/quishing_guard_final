"""run.py — Entry point for Quishing Guard API v2."""
import os
from app import create_app
from app.logger import get_logger
from app.engine.reputation import seed_database 

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
        log.info("🌱 Seeding database with built-in reputation lists...")
        seed_database()
        log.info("✅ Database seeded successfully.")
except Exception as e:
    log.error(f"⚠️ Database seed failed: {e}")

# ── 2. SECURITY WARNINGS (Runs on Render/Gunicorn boot) ──
if os.environ.get("ADMIN_PASSWORD", "change-me") == "change-me":
    log.warning("❌ SECURITY ALERT: ADMIN_PASSWORD is set to default!")
    log.warning("Please set a secure ADMIN_PASSWORD in your Render environment variables.")

# ── 3. LOCAL DEVELOPMENT EXECUTION (Ignored by Render) ──
if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    log.info(f"🚀 Starting Quishing Guard API v2 locally on port {port}")
    log.info(f"🛠️ Debug mode: {debug}")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
