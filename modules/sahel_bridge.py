"""
HARMATTAN — Live bridge to SAHEL SHIELD (periodic push of inventory + events).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Callable, Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.sahel_bridge")

_lock = threading.RLock()
_state = {
    "running": False,
    "url": "",
    "interval": 120,
    "last_push": None,
    "last_ok": False,
    "last_error": None,
    "pushes": 0,
    "thread": None,
}


def status() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "url": _state["url"],
            "interval": _state["interval"],
            "last_push": _state["last_push"],
            "last_ok": _state["last_ok"],
            "last_error": _state["last_error"],
            "pushes": _state["pushes"],
        }


def _post(url: str, payload: dict, timeout: float = 8) -> tuple[bool, str]:
    body = json.dumps(payload).encode()
    last_err = "unreachable"
    for path in ("/api/import/harmattan", "/api/events", "/api/ingest", "/api/alerts"):
        try:
            req = urllib.request.Request(
                url.rstrip("/") + path,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "HARMATTAN-Bridge/1"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if 200 <= resp.status < 300:
                    return True, path
        except Exception as e:
            last_err = str(e)
            continue
    return False, last_err


def push_once(url: str, payload_builder: Callable[[], dict]) -> dict:
    payload = payload_builder()
    ok, info = _post(url, payload)
    with _lock:
        _state["last_push"] = datetime.now().isoformat(timespec="seconds")
        _state["last_ok"] = ok
        _state["last_error"] = None if ok else info
        if ok:
            _state["pushes"] += 1
    return {"ok": ok, "info": info, "hosts": len(payload.get("hosts") or [])}


def start(url: str, interval: int, payload_builder: Callable[[], dict]) -> tuple[bool, str]:
    with _lock:
        if _state["running"]:
            return False, "Bridge déjà actif"
        _state["running"] = True
        _state["url"] = url.rstrip("/")
        _state["interval"] = max(30, int(interval))
        _state["last_error"] = None

        def _loop():
            while True:
                with _lock:
                    if not _state["running"]:
                        break
                    u = _state["url"]
                    iv = _state["interval"]
                try:
                    push_once(u, payload_builder)
                except Exception as e:
                    with _lock:
                        _state["last_error"] = str(e)
                        _state["last_ok"] = False
                for _ in range(iv):
                    with _lock:
                        if not _state["running"]:
                            return
                    time.sleep(1)

        t = threading.Thread(target=_loop, name="sahel-bridge", daemon=True)
        _state["thread"] = t
        t.start()
    return True, f"Bridge SAHEL démarré → {url} / {interval}s"


def stop() -> tuple[bool, str]:
    with _lock:
        if not _state["running"]:
            return False, "Bridge déjà arrêté"
        _state["running"] = False
    return True, "Bridge SAHEL arrêté"
