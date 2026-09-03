"""
HARMATTAN — Async job queue with SQLite metadata persistence.
"""
from __future__ import annotations

import json
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

from core.config import MAX_CONCURRENT_JOBS
from core.logging_setup import get_logger

try:
    from core import notifications as notifier
except Exception:
    notifier = None

log = get_logger("harmattan.jobs")


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class Job:
    id: str
    kind: str
    status: JobStatus = JobStatus.PENDING
    progress: int = 0
    message: str = ""
    result: Any = None
    error: Optional[str] = None
    created: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    started: Optional[str] = None
    finished: Optional[str] = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    def cancel(self) -> None:
        self._cancel.set()
        if self.status in (JobStatus.PENDING, JobStatus.RUNNING):
            self.status = JobStatus.CANCELLED
            self.message = "Annulé"
            self.finished = datetime.now().isoformat(timespec="seconds")

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def to_dict(self, include_result: bool = True) -> dict:
        d = {
            "id": self.id,
            "kind": self.kind,
            "status": self.status.value,
            "progress": self.progress,
            "message": self.message,
            "error": self.error,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
        }
        if include_result and self.status == JobStatus.DONE:
            d["result"] = self.result
        return d


def _persist(job: Job, include_result: bool = False) -> None:
    try:
        from core import db

        payload = job.to_dict(include_result=include_result and job.status == JobStatus.DONE)
        # Cap result size in DB
        if include_result and "result" in payload:
            raw = json.dumps(payload.get("result"), default=str)
            if len(raw) > 500_000:
                payload["result"] = {"_truncated": True, "size": len(raw)}
        db.upsert_job(payload)
    except Exception:
        log.debug("job persist skipped", exc_info=True)


class JobManager:
    def __init__(self, max_workers: int = MAX_CONCURRENT_JOBS):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="harmattan-job")
        self._max_kept = 50
        self._hydrated = False

    def hydrate(self) -> None:
        """Load recent finished jobs from SQLite (metadata only)."""
        if self._hydrated:
            return
        try:
            from core import db

            rows = db.list_jobs(limit=self._max_kept)
            with self._lock:
                for row in rows:
                    jid = row.get("id")
                    if not jid or jid in self._jobs:
                        continue
                    status = row.get("status") or "done"
                    # Don't revive running/pending as running — mark interrupted
                    if status in ("running", "pending"):
                        status = "error"
                        row["error"] = row.get("error") or "interrupted_by_restart"
                        row["message"] = "Interrompu (redémarrage)"
                        row["finished"] = row.get("finished") or datetime.now().isoformat(timespec="seconds")
                    try:
                        st = JobStatus(status)
                    except ValueError:
                        st = JobStatus.DONE
                    job = Job(
                        id=jid,
                        kind=row.get("kind") or "unknown",
                        status=st,
                        progress=int(row.get("progress") or 0),
                        message=row.get("message") or "",
                        error=row.get("error"),
                        created=row.get("created") or datetime.now().isoformat(timespec="seconds"),
                        started=row.get("started"),
                        finished=row.get("finished"),
                        result=row.get("result"),
                    )
                    self._jobs[jid] = job
            self._hydrated = True
            log.info("Hydrated %d jobs from DB", len(rows))
        except Exception:
            log.debug("job hydrate failed", exc_info=True)
            self._hydrated = True

    def submit(
        self,
        kind: str,
        fn: Callable[..., Any],
        *args,
        message: str = "En file d'attente…",
        **kwargs,
    ) -> Job:
        self.hydrate()
        job = Job(id=uuid.uuid4().hex[:12], kind=kind, message=message)
        with self._lock:
            self._jobs[job.id] = job
            self._trim()
        _persist(job)
        self._pool.submit(self._run, job, fn, args, kwargs)
        log.info("Job %s submitted kind=%s", job.id, kind)
        return job

    def _run(self, job: Job, fn: Callable, args: tuple, kwargs: dict) -> None:
        if job.cancelled:
            _persist(job)
            return
        job.status = JobStatus.RUNNING
        job.started = datetime.now().isoformat(timespec="seconds")
        job.message = "En cours…"
        job.progress = 5
        _persist(job)

        def progress(pct: int, msg: str = "") -> None:
            if job.cancelled:
                raise RuntimeError("cancelled")
            job.progress = max(0, min(100, int(pct)))
            if msg:
                job.message = msg
            try:
                if notifier:
                    notifier.publish({
                        "type": "job.update",
                        "job": job.to_dict(include_result=False),
                    })
            except Exception:
                pass

        try:
            import inspect

            sig = inspect.signature(fn)
            if "progress" in sig.parameters:
                kwargs = {**kwargs, "progress": progress}
            result = fn(*args, **kwargs)
            if job.cancelled:
                _persist(job)
                return
            job.result = result
            job.status = JobStatus.DONE
            job.progress = 100
            job.message = "Terminé"
            job.finished = datetime.now().isoformat(timespec="seconds")
            log.info("Job %s done kind=%s", job.id, job.kind)
            _persist(job, include_result=True)
            try:
                if notifier:
                    notifier.publish({"type": "job.update", "job": job.to_dict(include_result=False)})
            except Exception:
                pass
        except Exception as e:
            if str(e) == "cancelled" or job.cancelled:
                job.status = JobStatus.CANCELLED
                job.message = "Annulé"
            else:
                job.status = JobStatus.ERROR
                job.error = str(e)
                job.message = "Erreur"
                log.error("Job %s failed: %s\n%s", job.id, e, traceback.format_exc())
            job.finished = datetime.now().isoformat(timespec="seconds")
            _persist(job)
            try:
                if notifier:
                    notifier.publish({"type": "job.update", "job": job.to_dict(include_result=False)})
            except Exception:
                pass

    def get(self, job_id: str) -> Optional[Job]:
        self.hydrate()
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self, limit: int = 20) -> list[dict]:
        self.hydrate()
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)
            return [j.to_dict(include_result=False) for j in jobs[:limit]]

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job:
            return False
        job.cancel()
        _persist(job)
        return True

    def _trim(self) -> None:
        if len(self._jobs) <= self._max_kept:
            return
        finished = [
            j for j in self._jobs.values()
            if j.status in (JobStatus.DONE, JobStatus.ERROR, JobStatus.CANCELLED)
        ]
        finished.sort(key=lambda j: j.finished or j.created)
        while len(self._jobs) > self._max_kept and finished:
            old = finished.pop(0)
            self._jobs.pop(old.id, None)


manager = JobManager()
