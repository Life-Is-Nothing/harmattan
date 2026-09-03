"""Lightweight runtime metrics for observability."""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self.requests_total = 0
        self.requests_by_status: dict[str, int] = defaultdict(int)
        self.requests_by_path: dict[str, int] = defaultdict(int)
        self.auth_failures = 0
        self.rate_limited = 0
        self.errors_5xx = 0

    def record_request(self, path: str, status: int) -> None:
        bucket = path.split("?")[0]
        # normalize dynamic segments a bit
        parts = bucket.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "api":
            # keep /api/<resource> only for high-cardinality paths
            if parts[1] in ("jobs", "host", "hosts", "scans", "traffic") and len(parts) > 2:
                bucket = f"/api/{parts[1]}/…"
        with self._lock:
            self.requests_total += 1
            self.requests_by_status[str(status)] += 1
            self.requests_by_path[bucket] = self.requests_by_path[bucket] + 1
            if status == 401:
                self.auth_failures += 1
            if status == 429:
                self.rate_limited += 1
            if status >= 500:
                self.errors_5xx += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            top_paths = sorted(
                self.requests_by_path.items(), key=lambda x: x[1], reverse=True
            )[:20]
            return {
                "uptime_sec": int(time.time() - self.started),
                "requests_total": self.requests_total,
                "requests_by_status": dict(self.requests_by_status),
                "top_paths": [{"path": p, "count": c} for p, c in top_paths],
                "auth_failures": self.auth_failures,
                "rate_limited": self.rate_limited,
                "errors_5xx": self.errors_5xx,
            }

    def prometheus(self) -> str:
        snap = self.snapshot()
        lines = [
            "# HELP harmattan_up Always 1 when process is up",
            "# TYPE harmattan_up gauge",
            "harmattan_up 1",
            "# HELP harmattan_uptime_seconds Process uptime",
            "# TYPE harmattan_uptime_seconds gauge",
            f"harmattan_uptime_seconds {snap['uptime_sec']}",
            "# HELP harmattan_requests_total Total HTTP requests",
            "# TYPE harmattan_requests_total counter",
            f"harmattan_requests_total {snap['requests_total']}",
            "# HELP harmattan_auth_failures_total Auth failures",
            "# TYPE harmattan_auth_failures_total counter",
            f"harmattan_auth_failures_total {snap['auth_failures']}",
            "# HELP harmattan_rate_limited_total Rate limited responses",
            "# TYPE harmattan_rate_limited_total counter",
            f"harmattan_rate_limited_total {snap['rate_limited']}",
            "# HELP harmattan_errors_5xx_total Server errors",
            "# TYPE harmattan_errors_5xx_total counter",
            f"harmattan_errors_5xx_total {snap['errors_5xx']}",
        ]
        for code, count in snap["requests_by_status"].items():
            lines.append(
                f'harmattan_requests_by_status_total{{status="{code}"}} {count}'
            )
        return "\n".join(lines) + "\n"


metrics = Metrics()
