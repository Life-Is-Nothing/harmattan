"""
HARMATTAN Desktop GUI — Job Poller.
Periodically checks /api/jobs for running tasks and emits progress updates.
"""
from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from harmattan_gui.api.client import ApiClient


class JobPoller(QObject):
    """Polls job status every 2 seconds when jobs are active."""

    jobs_updated = pyqtSignal(list)  # list of job dicts
    job_completed = pyqtSignal(str)  # job_id

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self._poll)
        self._api = ApiClient.instance()
        self._active = False

    def start(self) -> None:
        self._active = True
        self._timer.start()

    def stop(self) -> None:
        self._active = False
        self._timer.stop()

    def _poll(self) -> None:
        def _on_jobs(jobs: list[Any]) -> None:
            if not self._active:
                return
            running = [j for j in jobs if j.get("status") in ("running", "pending", "queued")]
            self.jobs_updated.emit(jobs)
            # Check for newly completed jobs
            for j in jobs:
                if j.get("status") in ("done", "error", "cancelled"):
                    self.job_completed.emit(j.get("id", ""))

            # Stop timer if no more active jobs
            if not running:
                self._timer.stop()

        self._api.list_jobs(callback=_on_jobs)
