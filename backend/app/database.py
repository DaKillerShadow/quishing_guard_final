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
from sqlalchemy import MetaData

__all__ = ("db",)

# Standard naming convention for SQLAlchemy constraints.
# This prevents upgrade/downgrade errors if you ever use Alembic/Flask-Migrate.
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
db = SQLAlchemy(metadata=metadata)
