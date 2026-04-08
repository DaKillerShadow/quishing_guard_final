"""
app/logger.py — Structured Logging
=====================================
Replaces bare print() statements with Python's logging module.

Two handlers:
  console  — human-readable, coloured in dev, INFO level
  file     — JSON-lines format, rotates at 10 MB, keeps 5 backups

JSON-line format example:
  {"ts":"2025-01-01T12:00:00Z","level":"WARNING","module":"resolver",
   "msg":"SSRF attempt blocked","host":"192.168.1.1","ip":"10.0.0.5"}

The file path defaults to logs/quishing_guard.log next to run.py.
Override with LOG_FILE environment variable.

Usage (in any module):
  from .logger import get_logger
  log = get_logger(__name__)
  log.info("Scan completed", extra={"scan_id": sid, "score": 42})
"""
from __future__ import annotations
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone

# ── Configuration ────────────────────────────────────────────────────────────
# Use absolute paths to prevent issues with different working directories
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE  = os.environ.get("LOG_FILE", os.path.join(_BASE_DIR, "logs", "quishing_guard.log"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""
    
    def format(self, record: logging.LogRecord) -> str:
        # Core fields
        doc: dict = {
            "ts":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level":  record.levelname,
            "module": record.module,
            "msg":    record.getMessage(),
        }

        # 1. Safely attach extra context passed via log.info(..., extra={})
        # We filter out standard LogRecord attributes
        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename", 
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName", 
            "created", "msecs", "relativeCreated", "thread", "threadName", 
            "processName", "process", "message"
        }
        
        for key, val in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                doc[key] = val

        # 2. Attach Tracebacks if an exception occurred
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)

        # default=str handles objects like UUIDs or datetimes that aren't native JSON
        return json.dumps(doc, default=str)

class _ColourFormatter(logging.Formatter):
    """Human-readable coloured console output for local development."""
    _COLOURS = {
        "DEBUG":    "\033[36m", "INFO":     "\033[32m",
        "WARNING":  "\033[33m", "ERROR":    "\033[31m",
        "CRITICAL": "\033[35m",
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self._COLOURS.get(record.levelname, "")
        prefix = f"{colour}[{record.levelname[0]}]{self._RESET}"
        ts     = datetime.now(timezone.utc).strftime("%H:%M:%S")
        
        msg = f"{prefix} {ts}  {record.module:<15}  {record.getMessage()}"
        
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"
        return msg

def _build_logger() -> logging.Logger:
    logger = logging.getLogger("quishing_guard")
    if logger.handlers: return logger # Prevent duplicate handlers on hot-reload

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    logger.propagate = False # Prevent logs from leaking to the root logger

    # ── Detection Logic: TTY or Cloud? ──
    # If stdout is a real terminal (local dev), use colours. 
    # If it's a pipe (Docker/Render/Systemd), use JSON.
    use_json = not sys.stdout.isatty() or os.environ.get("RENDER") == "true"

    if use_json:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(_JsonFormatter())
        logger.addHandler(ch)
    else:
        # Local Console
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(_ColourFormatter())
        logger.addHandler(ch)

        # Local File (JSON-lines) for local forensic analysis
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir: os.makedirs(log_dir, exist_ok=True)
            
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=10*1024*1024, backupCount=3, encoding="utf-8"
        )
        fh.setFormatter(_JsonFormatter())
        logger.addHandler(fh)

    return logger

_logger = _build_logger()

# ── 3. Global Exception Hijack ──────────────────────────────────────────────
# This ensures that even "unhandled" errors that would normally just print 
# to stderr are captured in our structured JSON format.
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    _logger.critical("Uncaught Exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

def get_logger(name: str | None = None) -> logging.Logger:
    """Return a scoped child logger."""
    return _logger.getChild(name) if name else _logger
