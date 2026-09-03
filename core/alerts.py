"""Optional webhook alerts to HARMATTAN-HUB / Telegram."""
from __future__ import annotations

import os

import requests

from core.logging_setup import get_logger

log = get_logger("harmattan.alerts")
HUB_URL = os.environ.get("HARMATTAN_HUB_URL", "http://127.0.0.1:8077")
HUB_TOKEN = os.environ.get("HARMATTAN_HUB_TOKEN", os.environ.get("HHUB_TOKEN", ""))


def notify(text: str, source: str = "network", severity: str = "info") -> None:
    if not text:
        return
    headers = {"Content-Type": "application/json"}
    if HUB_TOKEN:
        headers["X-Hub-Token"] = HUB_TOKEN
    try:
        requests.post(
            f"{HUB_URL.rstrip('/')}/api/alert",
            json={"text": text, "source": source, "severity": severity},
            headers=headers,
            timeout=3,
        )
    except Exception as e:
        log.debug("alert skip: %s", e)
    try:
        requests.post(
            f"{HUB_URL.rstrip('/')}/api/event",
            json={
                "source": source,
                "title": text[:300],
                "severity": severity,
                "kind": "alert",
            },
            headers=headers,
            timeout=2,
        )
    except Exception as e:
        log.debug("event skip: %s", e)
