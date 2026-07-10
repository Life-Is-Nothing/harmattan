"""
HARMATTAN — Suricata eve.json tail (read-only integration).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

DEFAULT_PATHS = [
    os.environ.get("SURICATA_EVE", ""),
    "/var/log/suricata/eve.json",
    "/var/log/suricata/eve-alert.json",
    str(Path.home() / "suricata" / "eve.json"),
    "/tmp/suricata/eve.json",
]


def find_eve(path: str | None = None) -> Optional[Path]:
    candidates = [path] if path else []
    candidates += DEFAULT_PATHS
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if p.is_file() and p.stat().st_size >= 0:
            return p
    return None


def read_alerts(path: str | None = None, limit: int = 50) -> dict:
    eve = find_eve(path)
    if not eve:
        return {
            "ok": False,
            "available": False,
            "message": "Aucun eve.json Suricata trouvé (SURICATA_EVE=…)",
            "alerts": [],
            "path": None,
        }
    alerts = []
    try:
        # read last N lines efficiently
        with open(eve, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = min(size, 512_000)
            f.seek(-block, 2)
            data = f.read().decode("utf-8", errors="ignore")
        lines = data.splitlines()[-2000:]
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = ev.get("event_type")
            if et not in ("alert", "anomaly", "dns", "tls", "http"):
                if et != "alert":
                    continue
            if et != "alert" and len(alerts) > limit // 2:
                continue
            if et == "alert" or "alert" in ev:
                al = ev.get("alert") or {}
                alerts.append(
                    {
                        "timestamp": ev.get("timestamp"),
                        "event_type": et,
                        "src_ip": ev.get("src_ip"),
                        "dest_ip": ev.get("dest_ip"),
                        "src_port": ev.get("src_port"),
                        "dest_port": ev.get("dest_port"),
                        "proto": ev.get("proto"),
                        "signature": al.get("signature") or ev.get("event_type"),
                        "severity": al.get("severity"),
                        "category": al.get("category"),
                        "signature_id": al.get("signature_id"),
                    }
                )
            if len(alerts) >= limit:
                break
        alerts.reverse()
    except Exception as e:
        return {
            "ok": False,
            "available": True,
            "path": str(eve),
            "message": str(e),
            "alerts": [],
        }
    return {
        "ok": True,
        "available": True,
        "path": str(eve),
        "count": len(alerts),
        "alerts": alerts,
    }
