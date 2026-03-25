"""
app/models/db_models.py — SQLAlchemy Table Definitions
=======================================================
Three tables replace the old flat JSON files:

  BlocklistEntry  replaces  data/blocklist.json
  AllowlistEntry  replaces  data/allowlist.json
  ScanLog         new — audit trail of every analysis

Thread-safety note: because all writes go through SQLAlchemy
transactions, this is safe under Gunicorn multi-worker deployments.
The old JSON approach was NOT thread-safe (two workers could clobber
each other's writes on blocklist.json simultaneously).
"""
from __future__ import annotations
import secrets
from datetime import datetime, timezone
from ..database import db


def generate_scan_id() -> str:
    """Generate a random 16-character hex string for the ScanLog primary key."""
    return secrets.token_hex(8)


class BlocklistEntry(db.Model):
    """
    A domain flagged as malicious.
    Replaces the old data/blocklist.json flat file.

    is_approved controls the admin review workflow:
      False  — user-submitted, pending admin approval (shown in dashboard)
      True   — approved by admin (active in reputation checks)

    Seeded entries (added_by="seed") are pre-approved at startup.
    """
    __tablename__ = "blocklist"

    id          = db.Column(db.Integer, primary_key=True)
    domain      = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason      = db.Column(db.String(500), default="user_report")
    added_by    = db.Column(db.String(100), default="user")   # "user"|"admin"|"seed"
    is_approved = db.Column(db.Boolean, default=False, nullable=False, index=True)
    added_at    = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<BlocklistEntry id={self.id} domain='{self.domain}' approved={self.is_approved}>"

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "domain":      self.domain,
            "reason":      self.reason,
            "added_by":    self.added_by,
            "is_approved": self.is_approved,
            "added_at":    self.added_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.added_at else None,
        }


class AllowlistEntry(db.Model):
    """Operator-managed trusted domains (supplements the built-in set)."""
    __tablename__ = "allowlist"

    id       = db.Column(db.Integer, primary_key=True)
    domain   = db.Column(db.String(255), unique=True, nullable=False, index=True)
    added_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<AllowlistEntry id={self.id} domain='{self.domain}'>"

    def to_dict(self) -> dict:
        return {
            "id":       self.id,
            "domain":   self.domain,
            "added_at": self.added_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.added_at else None,
        }


class ScanLog(db.Model):
    """
    Audit record for every URL analysis.
    Enables:
      - Operator dashboard stats (scans/day, risk distribution)
      - Incident investigation (what did IP X scan at time T?)
      - SSRF attempt tracking (resolver errors logged here)

    client_ip is stored for abuse investigation but is NEVER
    returned in any public-facing API response.
    """
    __tablename__ = "scan_logs"

    # Fixed: Added secure default generator for string primary key
    id           = db.Column(db.String(16), primary_key=True, default=generate_scan_id)
    raw_url      = db.Column(db.Text, nullable=False)
    resolved_url = db.Column(db.Text)
    risk_score   = db.Column(db.Integer, default=0)
    risk_label   = db.Column(db.String(20))
    top_threat   = db.Column(db.String(50))
    hop_count    = db.Column(db.Integer, default=0)
    client_ip    = db.Column(db.String(45))
    scanned_at   = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<ScanLog id='{self.id}' score={self.risk_score} label='{self.risk_label}'>"

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "raw_url":      self.raw_url,
            "resolved_url": self.resolved_url,
            "risk_score":   self.risk_score,
            "risk_label":   self.risk_label,
            "top_threat":   self.top_threat,
            "hop_count":    self.hop_count,
            "scanned_at":   self.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.scanned_at else None,
        }
