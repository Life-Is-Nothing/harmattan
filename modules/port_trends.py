"""
HARMATTAN — Port-Trends: historical open-port tracking for reports.

Stores (append-only) the set of open ports per host across scans in a JSONL file under
data/, then produces a timeline: which ports appeared / disappeared over time. Useful
for spotting newly exposed services (a growth in attack surface) in a report.

Requires repeated scans over time; seeds from current data when first run.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from core.logging_setup import get_logger

log = get_logger("harmattan.port_trends")

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
TRENDS_FILE = os.path.join(DATA_DIR, "port_trends.jsonl")
MAX_SNAPSHOTS = 50


def _load_snapshots() -> list[dict]:
    snapshots = []
    if os.path.exists(TRENDS_FILE):
        try:
            with open(TRENDS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            snapshots.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError as e:
            log.debug("port_trends read: %s", e)
    return snapshots


def _append_snapshot(snap: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(TRENDS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(snap) + "\n")
    except OSError as e:
        log.debug("port_trends write: %s", e)


def record(hosts: list[dict]) -> dict:
    """Record the current open-port state; return a summary of the trend so far."""
    by_ip: dict[str, list[int]] = {}
    for h in hosts or []:
        ip = h.get("ip")
        if not ip:
            continue
        ports = sorted(
            {int(p.get("port")) for p in (h.get("ports") or []) if p.get("state") in (None, "open")}
        )
        if ports:
            by_ip[ip] = ports

    snap = {
        "ts": int(time.time()),
        "hosts": by_ip,
    }
    _append_snapshot(snap)

    # trim old
    snaps = _load_snapshots()
    if len(snaps) > MAX_SNAPSHOTS:
        try:
            with open(TRENDS_FILE, "w", encoding="utf-8") as f:
                for s in snaps[-MAX_SNAPSHOTS:]:
                    f.write(json.dumps(s) + "\n")
        except OSError as e:
            log.debug("port_trends trim: %s", e)

    return summarize()


def trends() -> dict:
    """Compute the timeline from stored snapshots (new ports per host over time)."""
    snaps = _load_snapshots()
    if not snaps:
        return {"history": [], "new_ports": {}, "count": 0, "generated_at": None}

    new_ports: dict[str, list[dict]] = {}
    for i, snap in enumerate(snaps):
        if i == 0:
            continue
        prev = snaps[i - 1].get("hosts") or {}
        cur = snap.get("hosts") or {}
        for ip, cur_ports in cur.items():
            prev_ports = prev.get(ip) or []
            added = sorted(set(cur_ports) - set(prev_ports))
            if added:
                new_ports.setdefault(ip, []).append(
                    {"at": snap["ts"], "added": added}
                )
    return {
        "history": snaps[-MAX_SNAPSHOTS:],
        "new_ports": new_ports,
        "count": len(new_ports),
        "generated_at": None,
    }


def summarize() -> dict:
    t = trends()
    # Return a lightweight summary dict usable directly as an API payload
    return {
        "snapshot_count": len(t["history"]),
        "hosts_with_new_ports": t["count"],
        "new_ports": t["new_ports"],
        "generated_at": None,
    }
