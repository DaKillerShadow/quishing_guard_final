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


LOG_FILE  = os.environ.get("LOG_FILE", os.path.join(
    os.path.dirname(__file__), "..", "logs", "quishing_guard.log"
))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict = {
            "ts":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level":  record.levelname,
            "module": record.module,
            "msg":    record.getMessage(),
        }
        # Attach any extra keyword arguments the caller passed
        for key, val in record.__dict__.items():
            if key not in {
                "name","msg","args","levelname","levelno","pathname",
                "filename","module","exc_info","exc_text","stack_info",
                "lineno","funcName","created","msecs","relativeCreated",
                "thread","threadName","processName","process","message",
            }:
                doc[key] = val
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


class _ColourFormatter(logging.Formatter):
    """Coloured console output for development."""
    _COLOURS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self._COLOURS.get(record.levelname, "")
        prefix = f"{colour}[{record.levelname[0]}]{self._RESET}"
        ts     = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return f"{prefix} {ts}  {record.module:<18}  {record.getMessage()}"


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("quishing_guard")
    if logger.handlers:          # already initialised (e.g., during testing)
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ── Console handler ──────────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(_ColourFormatter())
    logger.addHandler(ch)

    # ── Rotating file handler (JSON-lines) ───────────────────
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,   # 10 MB per file
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(_JsonFormatter())
    logger.addHandler(fh)

    # Don't propagate to the root logger (avoids duplicate output)
    logger.propagate = False
    return logger


_logger = _build_logger()


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger named quishing_guard.<name>."""
    if name:
        return _logger.getChild(name)
    return _logger
