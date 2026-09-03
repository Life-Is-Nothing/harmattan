"""
Lightweight in-memory pub/sub for server-sent events (SSE).
Not persistent; intended for live UI updates within a single process.
Multi-canal dispatch: Slack, Discord, Email, Syslog.
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Any, Dict, List

# optional persistence + rule evaluation
try:
    from core import db as _db
    import requests
except Exception:
    _db = None

_subscribers: List[queue.Queue] = []
_lock = threading.RLock()

# Notification channel dispatchers
_DISPATCHERS: dict[str, Any] = {}


def _load_dispatchers():
    """Lazy-load notification channel dispatchers."""
    if _DISPATCHERS:
        return
    try:
        from core.notify_slack import send as slack_send
        _DISPATCHERS["slack"] = slack_send
    except Exception:
        pass
    try:
        from core.notify_discord import send as discord_send
        _DISPATCHERS["discord"] = discord_send
    except Exception:
        pass
    try:
        from core.notify_email import send as email_send
        _DISPATCHERS["email"] = email_send
    except Exception:
        pass
    try:
        from core.notify_syslog import send as syslog_send
        _DISPATCHERS["syslog"] = syslog_send
    except Exception:
        pass


def _dispatch_to_channels(event: dict) -> None:
    """Send event to all enabled notification channels."""
    if _db is None:
        return
    try:
        channels = _db.list_notification_channels(enabled_only=True)
        if not channels:
            return
        _load_dispatchers()
        ev_type = event.get("type", "message")
        for ch in channels:
            canal = ch.get("canal", "")
            dispatcher = _DISPATCHERS.get(canal)
            if not dispatcher:
                continue
            # Check event filter
            events_filter = ch.get("events", "*")
            if events_filter != "*" and ev_type not in [e.strip() for e in events_filter.split(",")]:
                continue
            try:
                import json as _json

                config = {}
                raw_config = ch.get("config", "{}")
                if isinstance(raw_config, str):
                    config = _json.loads(raw_config)
                elif isinstance(raw_config, dict):
                    config = raw_config

                webhook_url = config.get("webhook_url", ch.get("webhook_url", ""))
                if not webhook_url and canal in ("email", "syslog"):
                    # Email and syslog use config for connection params
                    dispatcher(webhook_url, ev_type, event, config)
                elif webhook_url:
                    dispatcher(webhook_url, ev_type, event, config)
            except Exception as e:
                try:
                    from core.logging_setup import get_logger
                    get_logger("harmattan.notifications").error(
                        "Channel dispatch failed (%s): %s", canal, e
                    )
                except Exception:
                    pass
    except Exception:
        pass


def subscribe(timeout: float = 0.5) -> queue.Queue:
    q: queue.Queue = queue.Queue()
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


def publish(event: Dict) -> None:
    """Publish event to all subscribers (non-blocking) and persist + evaluate alert rules."""
    # Dispatch to configured notification channels (Slack, Discord, etc.)
    try:
        _dispatch_to_channels(event)
    except Exception:
        pass

    # persist if DB available
    try:
        if _db:
            try:
                _db.save_notification(event.get('type','message'), event)
            except Exception:
                pass
    except Exception:
        pass

    # evaluate alert rules (simple matching)
    try:
        if _db:
            try:
                rules = _db.list_alert_rules()
                for r in rules:
                    et = r.get('event_type')
                    cond = (r.get('condition') or '').strip()
                    if et and et != event.get('type'):
                        continue
                    # simple contains match on JSON payload
                    if cond:
                        if cond.startswith('json:'):
                            pattern = cond.split(':',1)[1]
                            if pattern and pattern in str(event):
                                # fire webhook if present
                                if r.get('webhook'):
                                    try:
                                        requests.post(r.get('webhook'), json=event, timeout=3)
                                    except Exception:
                                        pass
                                # continue to next rule
                        else:
                            if cond not in str(event):
                                continue
                    else:
                        # no condition -> always match
                        if r.get('webhook'):
                            try:
                                requests.post(r.get('webhook'), json=event, timeout=3)
                            except Exception:
                                pass
            except Exception:
                pass
    except Exception:
        pass

    with _lock:
        subs = list(_subscribers)
    for q in subs:
        try:
            q.put_nowait(event)
        except Exception:
            # If a subscriber queue is full or broken, ignore
            pass


# housekeeping: periodically purge dead subscribers (optional)
def _purge_worker() -> None:
    while True:
        time.sleep(30)
        with _lock:
            for q in list(_subscribers):
                # no robust way to detect closed queues; skip
                pass


# start purge thread as daemon
_thread = threading.Thread(target=_purge_worker, daemon=True)
_thread.start()
