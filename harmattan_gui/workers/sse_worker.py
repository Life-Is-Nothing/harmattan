"""
HARMATTAN Desktop GUI — SSE Worker.
Reads the /api/stream SSE endpoint in a background thread and emits Qt signals.
"""
from __future__ import annotations

import json
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from harmattan_gui.api import endpoints as E
from harmattan_gui.api.client import ApiClient


class SseWorker(QThread):
    """Background thread that consumes the SSE event stream."""

    event_received = pyqtSignal(str, dict)  # event_type, data
    connected = pyqtSignal()
    disconnected = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False
        self._api = ApiClient.instance()

    def run(self) -> None:
        """Connect to SSE stream and process events."""
        self._running = True
        client = ApiClient.instance()

        while self._running:
            try:
                import requests

                url = f"{E.BASE_URL}/api/stream"
                headers = {}
                if self._api._token:
                    headers["X-Harmattan-Token"] = self._api._token

                resp = requests.get(url, headers=headers, stream=True, timeout=60)
                self.connected.emit()

                for line in resp.iter_lines(decode_unicode=True):
                    if not self._running:
                        break
                    if line.startswith("data:"):
                        data_str = line[5:].strip()
                        if not data_str:
                            continue
                        try:
                            data = json.loads(data_str)
                            ev_type = data.pop("type", "message")
                            self.event_received.emit(ev_type, data)
                        except json.JSONDecodeError:
                            pass
                    elif line.startswith("event:"):
                        pass  # event type is already embedded in data

            except (requests.ConnectionError, requests.Timeout) as e:
                self.disconnected.emit()
                if self._running:
                    self.msleep(2000)  # reconnect delay
            except Exception:
                self.disconnected.emit()
                if self._running:
                    self.msleep(2000)
            finally:
                self.msleep(500)

    def stop(self) -> None:
        self._running = False
        self.wait(3000)
