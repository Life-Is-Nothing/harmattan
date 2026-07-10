"""ARP continuous monitoring — periodic scan + hub alerts on new hosts."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from core.alerts import notify as alert_notify
from core.logging_setup import get_logger
from core.state import state

log = get_logger("harmattan.monitor")

_lock = threading.Lock()
_state: dict[str, Any] = {
    "running": False,
    "thread": None,
    "stop": None,
    "interval": 60,
    "cycles": 0,
    "last_error": None,
    "last_new": [],
}


def status() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "interval": _state["interval"],
            "cycles": _state["cycles"],
            "last_error": _state["last_error"],
            "last_new": list(_state["last_new"] or []),
        }


def start(interval: int = 60, scan_fn: Optional[Callable] = None) -> tuple[bool, str]:
    with _lock:
        if _state["running"]:
            return False, "Monitoring déjà actif"
        stop = threading.Event()
        _state["stop"] = stop
        _state["running"] = True
        _state["interval"] = max(20, min(int(interval), 600))
        _state["last_error"] = None

        def loop():
            from modules import arp_scanner
            from modules.diff_scan import diff_arp

            while not stop.is_set():
                try:
                    prev = (state.get("last_arp") or {}).get("hosts", [])
                    if scan_fn:
                        result = scan_fn()
                    else:
                        result = arp_scanner.scan_network(progress=None)
                    if result and result.get("hosts") is not None:
                        state.set("last_arp", result)
                        cur = result.get("hosts") or []
                        d = diff_arp(prev, cur) if prev else {"appeared": cur}
                        appeared = d.get("appeared") or d.get("new") or []
                        if appeared:
                            names = [
                                f"{h.get('ip')} ({h.get('vendor') or h.get('hostname') or '?'})"
                                for h in appeared[:8]
                            ]
                            msg = f"HARMATTAN: {len(appeared)} nouvel(aux) hôte(s): " + ", ".join(names)
                            alert_notify(msg, source="network-monitor")
                            with _lock:
                                _state["last_new"] = names
                        with _lock:
                            _state["cycles"] += 1
                            _state["last_error"] = None
                except Exception as e:
                    log.exception("monitor cycle")
                    with _lock:
                        _state["last_error"] = str(e)
                stop.wait(_state["interval"])
            with _lock:
                _state["running"] = False

        t = threading.Thread(target=loop, name="harmattan-monitor", daemon=True)
        _state["thread"] = t
        t.start()
        return True, f"Monitoring ARP démarré ({_state['interval']}s)"


def stop() -> tuple[bool, str]:
    with _lock:
        if not _state["running"]:
            return False, "Monitoring déjà arrêté"
        if _state["stop"]:
            _state["stop"].set()
        return True, "Arrêt monitoring…"
