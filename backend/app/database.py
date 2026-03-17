"""
app/database.py — Shared SQLAlchemy instance
=============================================
Imported by models and the app factory. Kept in its own module to
prevent circular imports between __init__.py, models, and routes.

Supported DATABASE_URL values:
  sqlite:///quishing_guard.db          (default, zero-config)
  postgresql://user:pass@host:5432/db  (production)
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
