"""
Thread-safe application state for HARMATTAN.
"""
from __future__ import annotations

import threading
from typing import Any, Optional


class AppState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {
            "last_arp": None,
            "last_nmap": None,
            "last_vuln": None,
            "last_attack": None,
            "last_network": None,
            "last_home": None,
            "capture": None,
            "new_devices": [],
        }

    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, **kwargs) -> None:
        with self._lock:
            self._data.update(kwargs)

    def snapshot_keys(self, *keys: str) -> dict:
        with self._lock:
            return {k: self._data.get(k) for k in keys}

    @property
    def capture(self) -> Optional[Any]:
        with self._lock:
            return self._data.get("capture")

    @capture.setter
    def capture(self, value: Optional[Any]) -> None:
        with self._lock:
            self._data["capture"] = value


state = AppState()
