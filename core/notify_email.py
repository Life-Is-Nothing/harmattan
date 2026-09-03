"""
HARMATTAN — SMTP email notification dispatcher.
"""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any

log = logging.getLogger("harmattan.notify.email")


def send(webhook_url: str, event_type: str, payload: dict, config: dict | None = None) -> bool:
    """Send a notification via SMTP email."""
    cfg = config or {}
    smtp_host = cfg.get("smtp_host", "localhost")
    smtp_port = int(cfg.get("smtp_port", "25"))
    smtp_user = cfg.get("smtp_user", "")
    smtp_pass = cfg.get("smtp_pass", "")
    use_tls = cfg.get("smtp_tls", False)
    from_addr = cfg.get("from", "harmattan@localhost")
    to_addrs = cfg.get("to", "").split(",")

    if not to_addrs or not to_addrs[0]:
        log.warning("Email notification: no recipients configured")
        return False

    title = payload.get("title", event_type)
    message = payload.get("message", payload.get("detail", ""))
    severity = payload.get("severity", "info")

    body = f"""HARMATTAN Alert
===============
Type:     {event_type}
Sévérité: {severity}
Titre:    {title}
Time:     {payload.get('ts', '')}

{message}
"""
    msg = MIMEText(body)
    msg["Subject"] = f"[HARMATTAN] {title[:80]}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        log.debug("Email notification sent: %s", event_type)
        return True
    except Exception as e:
        log.error("Email notification failed: %s", e)
        return False
