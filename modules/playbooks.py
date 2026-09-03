"""
HARMATTAN — Engagement playbooks (1-click audit chains).
Authorized networks only.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Optional

# Built-in playbook definitions (steps are logical; runner maps to real actions)
PLAYBOOKS: dict[str, dict[str, Any]] = {
    "quick_lan": {
        "id": "quick_lan",
        "name": "Scan rapide LAN",
        "description": "ARP enrichi + surface d'attaque + baseline snapshot",
        "steps": ["arp", "attack_surface", "baseline", "risk"],
        "estimate_min": 2,
    },
    "iot_audit": {
        "id": "iot_audit",
        "name": "Audit IoT",
        "description": "ARP light + mDNS/SSDP + passive recon + surface",
        "steps": ["arp_light", "mdns", "passive", "attack_surface", "risk"],
        "estimate_min": 3,
    },
    "pre_engagement": {
        "id": "pre_engagement",
        "name": "Pré-engagement",
        "description": "ARP → nmap services → surface → baseline → rapport HTML",
        "steps": ["arp", "nmap_service", "attack_surface", "baseline", "report", "risk"],
        "estimate_min": 15,
    },
    "full_recon": {
        "id": "full_recon",
        "name": "Recon complète",
        "description": "ARP + passive + nmap + intel light + drift + risk",
        "steps": ["arp", "passive", "mdns", "nmap_service", "attack_surface", "baseline_diff", "risk"],
        "estimate_min": 20,
    },
    "drift_check": {
        "id": "drift_check",
        "name": "Contrôle drift",
        "description": "ARP rapide + diff contre baseline active",
        "steps": ["arp", "baseline_diff", "risk"],
        "estimate_min": 2,
    },
}


def list_playbooks() -> list[dict]:
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "description": p["description"],
            "steps": p["steps"],
            "estimate_min": p.get("estimate_min"),
        }
        for p in PLAYBOOKS.values()
    ]


def get_playbook(playbook_id: str) -> Optional[dict]:
    return PLAYBOOKS.get(playbook_id)


def run_playbook(
    playbook_id: str,
    *,
    subnet: str | None = None,
    iface: str | None = None,
    progress: Optional[Callable[[int, str], None]] = None,
    ctx: dict | None = None,
) -> dict[str, Any]:
    """
    Execute a playbook. `ctx` may inject callables:
      do_arp(subnet, iface, enrich, light) -> dict
      do_nmap(target, profile) -> dict
      do_mdns() -> dict
      do_passive(timeout) -> dict
      do_attack(arp_hosts, nmap_hosts) -> dict
      do_baseline_save(label) -> dict
      do_baseline_diff() -> dict
      do_report() -> dict
      do_risk() -> dict
    """
    pb = get_playbook(playbook_id)
    if not pb:
        return {"ok": False, "error": "unknown_playbook", "id": playbook_id}

    ctx = ctx or {}
    started = datetime.now().isoformat(timespec="seconds")
    results: dict[str, Any] = {}
    steps = pb["steps"]
    n = max(1, len(steps))
    errors: list[str] = []

    def _prog(i: int, msg: str):
        if progress:
            progress(int((i / n) * 100), msg)

    for i, step in enumerate(steps):
        _prog(i, f"Étape {step}…")
        try:
            if step == "arp":
                fn = ctx.get("do_arp")
                results["arp"] = fn(subnet, iface, True, False) if fn else {"skipped": True}
            elif step == "arp_light":
                fn = ctx.get("do_arp")
                results["arp"] = fn(subnet, iface, False, True) if fn else {"skipped": True}
            elif step == "nmap_service":
                fn = ctx.get("do_nmap")
                target = subnet or (results.get("arp") or {}).get("meta", {}).get("subnet") or ""
                results["nmap"] = fn(target, "service") if fn and target else {"skipped": True, "reason": "no_target"}
            elif step == "mdns":
                fn = ctx.get("do_mdns")
                results["mdns"] = fn() if fn else {"skipped": True}
            elif step == "passive":
                fn = ctx.get("do_passive")
                results["passive"] = fn(3.0) if fn else {"skipped": True}
            elif step == "attack_surface":
                fn = ctx.get("do_attack")
                arp_h = (results.get("arp") or {}).get("hosts") or ctx.get("arp_hosts") or []
                nmap_h = (results.get("nmap") or {}).get("hosts") or ctx.get("nmap_hosts") or []
                results["attack"] = fn(arp_h, nmap_h) if fn else {"skipped": True}
            elif step == "baseline":
                fn = ctx.get("do_baseline_save")
                results["baseline"] = fn(f"playbook-{playbook_id}") if fn else {"skipped": True}
            elif step == "baseline_diff":
                fn = ctx.get("do_baseline_diff")
                results["drift"] = fn() if fn else {"skipped": True}
            elif step == "report":
                fn = ctx.get("do_report")
                results["report"] = fn() if fn else {"skipped": True}
            elif step == "risk":
                fn = ctx.get("do_risk")
                results["risk"] = fn() if fn else {"skipped": True}
            else:
                results[step] = {"skipped": True, "reason": "unknown_step"}
        except Exception as e:
            errors.append(f"{step}: {e}")
            results[step] = {"ok": False, "error": str(e)[:200]}

    _prog(n, "Terminé")
    finished = datetime.now().isoformat(timespec="seconds")
    return {
        "ok": not errors,
        "playbook": playbook_id,
        "name": pb["name"],
        "started": started,
        "finished": finished,
        "steps": steps,
        "results": results,
        "errors": errors,
    }
