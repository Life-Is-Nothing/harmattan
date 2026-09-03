"""
HARMATTAN — Live network risk dashboard (grade A–F + top remediations).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


def build_risk_dashboard(
    *,
    arp: dict | None = None,
    nmap: dict | None = None,
    attack: dict | None = None,
    drift: dict | None = None,
    known_count: int = 0,
    new_devices: list | None = None,
    tags_summary: dict | None = None,
) -> dict[str, Any]:
    arp = arp or {}
    nmap = nmap or {}
    attack = attack or {}
    new_devices = new_devices or []
    tags_summary = tags_summary or {}

    hosts_arp = arp.get("hosts") or []
    hosts_nmap = nmap.get("hosts") or []
    grade = attack.get("grade") or "—"
    score = attack.get("risk_score")
    if score is None:
        score = 0 if grade in ("A", "—") else 30

    # Adjust score for drift / new devices
    if drift and (drift.get("summary") or {}).get("has_drift"):
        s = drift["summary"]
        score = min(100, int(score) + s.get("appeared", 0) * 3 + s.get("changed", 0) * 2)
        if grade == "A" and score >= 20:
            grade = "B"
        if score >= 50 and grade in ("A", "B", "C"):
            grade = "D" if score >= 50 else grade

    if len(new_devices) >= 3:
        score = min(100, int(score) + 10)

    # Recalculate grade from score if attack missing
    if not attack.get("grade"):
        if score >= 70:
            grade = "F"
        elif score >= 50:
            grade = "D"
        elif score >= 35:
            grade = "C"
        elif score >= 20:
            grade = "B"
        elif hosts_arp or hosts_nmap:
            grade = "A"
        else:
            grade = "—"

    remediations = list(attack.get("recommendations") or [])[:10]
    top_hosts = []
    for h in (attack.get("hosts") or [])[:10]:
        top_hosts.append({
            "ip": h.get("ip"),
            "hostname": h.get("hostname"),
            "max_risk": h.get("max_risk"),
            "exposure_count": h.get("exposure_count"),
            "role": h.get("role"),
        })

    drift_summary = (drift or {}).get("summary") if drift else None

    return {
        "ok": True,
        "time": datetime.now().isoformat(timespec="seconds"),
        "grade": grade,
        "risk_score": int(score),
        "hosts_arp": len(hosts_arp),
        "hosts_nmap": len(hosts_nmap),
        "known_hosts": known_count,
        "new_devices": len(new_devices),
        "total_exposures": attack.get("total_exposures") or 0,
        "risk_counts": attack.get("risk_counts") or {},
        "top_hosts": top_hosts,
        "top_remediations": remediations,
        "drift": drift_summary,
        "tags": tags_summary,
        "status": _status_label(grade, score),
    }


def _status_label(grade: str, score: int) -> str:
    if grade == "—":
        return "no_data"
    if grade in ("A", "B") and score < 25:
        return "healthy"
    if grade in ("B", "C"):
        return "watch"
    if grade == "D":
        return "elevated"
    return "critical"
