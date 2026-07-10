"""
HARMATTAN — Scheduled ARP scan + optional HTML report.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from core.config import REPORTS_DIR
from core.logging_setup import get_logger

log = get_logger("harmattan.scheduler")

_lock = threading.RLock()
_state = {
    "running": False,
    "interval": 300,
    "with_report": False,
    "last_run": None,
    "last_ok": False,
    "last_error": None,
    "last_hosts": 0,
    "cycles": 0,
    "thread": None,
}


def status() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "interval": _state["interval"],
            "with_report": _state["with_report"],
            "last_run": _state["last_run"],
            "last_ok": _state["last_ok"],
            "last_error": _state["last_error"],
            "last_hosts": _state["last_hosts"],
            "cycles": _state["cycles"],
        }


def start(
    scan_fn: Callable[[], dict],
    interval: int = 300,
    with_report: bool = False,
    report_fn: Optional[Callable[[dict], Path | None]] = None,
) -> tuple[bool, str]:
    with _lock:
        if _state["running"]:
            return False, "Scheduler déjà actif"
        _state["running"] = True
        _state["interval"] = max(60, int(interval))
        _state["with_report"] = bool(with_report)
        _state["last_error"] = None

        def loop():
            while True:
                with _lock:
                    if not _state["running"]:
                        break
                    iv = _state["interval"]
                    do_rep = _state["with_report"]
                try:
                    result = scan_fn() or {}
                    hosts = 0
                    if isinstance(result, dict):
                        hosts = result.get("count") or len(result.get("hosts") or [])
                    with _lock:
                        _state["last_run"] = datetime.now().isoformat(timespec="seconds")
                        _state["last_ok"] = True
                        _state["last_error"] = None
                        _state["last_hosts"] = hosts
                        _state["cycles"] += 1
                    if do_rep and report_fn:
                        try:
                            report_fn(result)
                        except Exception as e:
                            log.warning("scheduled report failed: %s", e)
                    log.info("scheduled scan ok hosts=%s", hosts)
                except Exception as e:
                    log.exception("scheduled scan")
                    with _lock:
                        _state["last_run"] = datetime.now().isoformat(timespec="seconds")
                        _state["last_ok"] = False
                        _state["last_error"] = str(e)
                for _ in range(iv):
                    with _lock:
                        if not _state["running"]:
                            return
                    time.sleep(1)

        t = threading.Thread(target=loop, name="harmattan-sched", daemon=True)
        _state["thread"] = t
        t.start()
    return True, f"Scheduler démarré · intervalle {interval}s"


def stop() -> tuple[bool, str]:
    with _lock:
        if not _state["running"]:
            return False, "Scheduler déjà arrêté"
        _state["running"] = False
    return True, "Scheduler arrêté"
