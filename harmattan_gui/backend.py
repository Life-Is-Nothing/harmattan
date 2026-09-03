"""
HARMATTAN Desktop GUI — Backend Process Manager.
Manages the Flask backend as a QProcess child.
"""
from __future__ import annotations

import os
import sys
import json
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from harmattan_gui.api.client import ApiClient


class BackendProcess(QObject):
    """Manages the Flask backend as a subprocess."""

    started = pyqtSignal()
    stopped = pyqtSignal(int)  # exit code
    error = pyqtSignal(str)
    health_ok = pyqtSignal()
    health_fail = pyqtSignal(str)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._process: Optional[QProcess] = None
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(500)
        self._health_timer.timeout.connect(self._check_health)
        self._health_retries = 0
        self._max_health_retries = 30  # 15 seconds total
        self._port = int(os.environ.get("HARMATTAN_PORT", "8088"))
        self._host = os.environ.get("HARMATTAN_HOST", "127.0.0.1")
        self._https = os.environ.get("HARMATTAN_HTTPS", "0") == "1"
        self._backend_script = self._find_backend_script()
        self._api = ApiClient.instance()

    def _find_backend_script(self) -> str:
        """Find app.py relative to this package."""
        pkg_dir = Path(__file__).resolve().parent.parent  # harmattan/
        app_py = pkg_dir / "app.py"
        if app_py.is_file():
            return str(app_py)
        # Fallback: guess from cwd
        return os.path.join(os.getcwd(), "app.py")

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.state() == QProcess.ProcessState.Running

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        """Start the Flask backend process."""
        if self.is_running:
            return

        if not Path(self._backend_script).is_file():
            self.error.emit(f"Backend script not found: {self._backend_script}")
            return

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.ForwardedChannels)

        env = self._process.processEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("HARMATTAN_PORT", str(self._port))
        env.insert("HARMATTAN_HOST", self._host)
        if self._https:
            env.insert("HARMATTAN_HTTPS", "1")
        self._process.setProcessEnvironment(env)

        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)

        args = ["--daemon", "--host", self._host, "--port", str(self._port)]
        if self._https:
            args.extend(["--https", "1"])

        self._process.start(sys.executable, [self._backend_script, "serve"] + args)

        if not self._process.waitForStarted(5000):
            self.error.emit("Failed to start backend process")
            return

        self._health_retries = 0
        self._health_timer.start()

    def stop(self) -> None:
        """Stop the backend process gracefully."""
        if not self.is_running:
            return

        # Try graceful shutdown via API
        self._api.post("/api/shutdown", callback=lambda r: self._process.terminate())

        if not self._process.waitForFinished(5000):
            self._process.kill()
            self._process.waitForFinished(2000)

    def _check_health(self) -> None:
        """Poll the backend health endpoint."""
        def _on_health(data):
            self._health_timer.stop()
            self.health_ok.emit()
            self.started.emit()

        def _on_error(err):
            self._health_retries += 1
            if self._health_retries >= self._max_health_retries:
                self._health_timer.stop()
                self.health_fail.emit(
                    f"Backend not responding after {self._max_health_retries * 0.5}s"
                )

        self._api.check_health(callback=_on_health, errback=_on_error)

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self.stopped.emit(exit_code)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        self.error.emit(f"Backend process error: {error}")
