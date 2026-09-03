"""
HARMATTAN — Discord webhook notification dispatcher.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger("harmattan.notify.discord")


def send(webhook_url: str, event_type: str, payload: dict, config: dict | None = None) -> bool:
    """Send a notification to Discord via webhook."""
    title = payload.get("title", event_type)
    message = payload.get("message", payload.get("detail", ""))
    severity = payload.get("severity", "info")

    colors = {"critique": 15548997, "haute": 15105570, "moyenne": 16776960, "info": 5793266}
    color = colors.get(severity, 10070709)

    embed = {
        "title": title[:256],
        "color": color,
        "fields": [
            {"name": "Type", "value": event_type, "inline": True},
            {"name": "Sévérité", "value": severity, "inline": True},
        ],
        "timestamp": payload.get("ts", ""),
    }
    if message:
        embed["description"] = message[:4096]

    data = {"embeds": [embed], "content": f"**HARMATTAN Alert** — {title[:80]}"}

    try:
        resp = requests.post(webhook_url, json=data, timeout=10)
        resp.raise_for_status()
        log.debug("Discord notification sent: %s", event_type)
        return True
    except requests.RequestException as e:
        log.error("Discord notification failed: %s", e)
        return False
