"""
HARMATTAN — Syslog notification dispatcher.
"""
from __future__ import annotations

import logging
import logging.handlers
from typing import Any

log = logging.getLogger("harmattan.notify.syslog")

_syslog_handler = None


def _ensure_handler(config: dict | None) -> logging.Handler:
    """Get or create the syslog handler."""
    global _syslog_handler
    if _syslog_handler is not None:
        return _syslog_handler

    cfg = config or {}
    host = cfg.get("syslog_host", "localhost")
    port = int(cfg.get("syslog_port", "514"))
    facility = logging.handlers.SysLogHandler.LOG_USER

    try:
        _syslog_handler = logging.handlers.SysLogHandler(address=(host, port), facility=facility)
        _syslog_handler.setLevel(logging.INFO)
        _syslog_handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    except Exception as e:
        log.error("Failed to create SysLogHandler: %s", e)
        _syslog_handler = logging.NullHandler()

    return _syslog_handler


def send(webhook_url: str, event_type: str, payload: dict, config: dict | None = None) -> bool:
    """Send a notification via syslog."""
    title = payload.get("title", event_type)
    message = payload.get("message", payload.get("detail", ""))
    severity = payload.get("severity", "info")

    syslog_level = logging.INFO
    if severity in ("critique", "haute"):
        syslog_level = logging.ERROR
    elif severity == "moyenne":
        syslog_level = logging.WARNING

    handler = _ensure_handler(config)
    sys_logger = logging.getLogger("harmattan.syslog")
    sys_logger.addHandler(handler)
    sys_logger.setLevel(logging.INFO)

    sys_logger.log(syslog_level, f"[{event_type}] {title} — {message[:200]}")
    return True
