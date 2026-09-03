"""
HARMATTAN — Slack webhook notification dispatcher.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

log = logging.getLogger("harmattan.notify.slack")


def send(webhook_url: str, event_type: str, payload: dict, config: dict | None = None) -> bool:
    """Send a notification to Slack via webhook."""
    title = payload.get("title", event_type)
    message = payload.get("message", payload.get("detail", ""))
    severity = payload.get("severity", "info")

    colors = {"critique": "#DC2626", "haute": "#EA580C", "moyenne": "#EAB308", "info": "#3B82F6"}
    color = colors.get(severity, "#6B7280")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"HARMATTAN: {title[:80]}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Type*: {event_type}\n*Sévérité*: {severity}"},
        },
    ]
    if message:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"```{message[:2000]}```"},
        })

    data = {
        "attachments": [{
            "color": color,
            "blocks": blocks,
            "ts": payload.get("ts", ""),
        }],
    }

    try:
        resp = requests.post(webhook_url, json=data, timeout=10)
        resp.raise_for_status()
        log.debug("Slack notification sent: %s", event_type)
        return True
    except requests.RequestException as e:
        log.error("Slack notification failed: %s", e)
        return False
