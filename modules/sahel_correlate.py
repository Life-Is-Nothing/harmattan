"""
HARMATTAN ↔ SAHEL SHIELD — corrélation alertes / paquets.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Callable, Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.sahel_correlate")


def _post_json(url: str, payload: dict, timeout: float = 8) -> tuple[bool, Any]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "HARMATTAN-Correlate/1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return True, json.loads(raw)
            except json.JSONDecodeError:
                return True, {"raw": raw}
    except Exception as e:
        return False, {"error": str(e)}


def _get_json(url: str, timeout: float = 5) -> tuple[bool, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return True, json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        return False, {"error": str(e)}


def local_correlate(packets: list[dict], alerts: list[dict]) -> dict:
    """
    Match alertes (src/dst/dport) against packet index.
    Returns enriched matches.
    """
    # index packets by IP
    by_ip: dict[str, list] = {}
    for p in packets:
        for ip in (p.get("src"), p.get("dst")):
            if not ip or ip == "—":
                continue
            by_ip.setdefault(ip, []).append(p)

    matches = []
    unmatched = []
    for a in alerts:
        src = a.get("src") or (a.get("flow") or {}).get("src")
        dst = a.get("dst") or (a.get("flow") or {}).get("dst")
        dport = a.get("dport") or (a.get("flow") or {}).get("dport")
        related = []
        seen = set()
        for ip in (src, dst):
            if not ip:
                continue
            for p in by_ip.get(ip, []):
                if p.get("no") in seen:
                    continue
                # prefer same port
                score = 1
                if dport and (p.get("dport") == dport or p.get("sport") == dport):
                    score += 3
                if src and dst and {p.get("src"), p.get("dst")} == {src, dst}:
                    score += 2
                related.append({**p, "match_score": score})
                seen.add(p.get("no"))
        related.sort(key=lambda x: -x.get("match_score", 0))
        related = related[:15]
        entry = {
            "alert_id": a.get("id"),
            "title": a.get("title") or a.get("severity"),
            "severity": a.get("severity"),
            "src": src,
            "dst": dst,
            "dport": dport,
            "status": a.get("status"),
            "packet_count": len(related),
            "packets": related,
            "top_packet_nos": [p.get("no") for p in related[:8]],
        }
        if related:
            matches.append(entry)
        else:
            unmatched.append(entry)

    return {
        "ok": True,
        "method": "local",
        "matched": len(matches),
        "unmatched": len(unmatched),
        "matches": matches,
        "unmatched_alerts": unmatched[:30],
        "at": datetime.now().isoformat(timespec="seconds"),
    }


def push_and_correlate(
    sahel_url: str,
    packets: list[dict],
    hosts: list | None = None,
    extra: dict | None = None,
) -> dict:
    """
    POST packets (+ hosts) to Sahel /api/correlate/harmattan
    Falls back to /api/import/harmattan with packets field.
    """
    base = sahel_url.rstrip("/")
    payload = {
        "format": "harmattan-correlate",
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "packets": packets,
        "hosts": hosts or [],
        "source": "harmattan-correlate",
        **(extra or {}),
    }
    for path in ("/api/correlate/harmattan", "/api/import/harmattan"):
        ok, data = _post_json(base + path, payload)
        if ok and isinstance(data, dict) and data.get("ok") is not False:
            data.setdefault("via", path)
            data["sahel_url"] = base
            return data
        last = data
    return {
        "ok": False,
        "message": "Sahel non joignable pour corrélation",
        "detail": last if "last" in dir() else None,
        "sahel_url": base,
    }


def fetch_sahel_alerts(sahel_url: str, limit: int = 100) -> list[dict]:
    """Best-effort: needs open API or will fail — Sahel alerts often need auth."""
    base = sahel_url.rstrip("/")
    for path in (f"/api/alerts?limit={limit}", f"/api/alerts"):
        ok, data = _get_json(base + path)
        if ok:
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "alerts" in data:
                return data["alerts"]
    return []
