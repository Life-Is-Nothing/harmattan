"""
HARMATTAN — Network baseline snapshots and drift detection.
Compare current ARP/nmap state against a saved baseline.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Optional


def _host_key(h: dict) -> str:
    mac = (h.get("mac") or "").upper().strip()
    if mac and mac != "FF:FF:FF:FF:FF:FF":
        return f"mac:{mac}"
    ip = (h.get("ip") or "").strip()
    return f"ip:{ip}" if ip else ""


def _ports_set(h: dict) -> set[int]:
    ports: set[int] = set()
    for p in h.get("open_ports") or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            pass
    for p in h.get("ports") or []:
        if isinstance(p, dict):
            if p.get("state") in (None, "open", "open|filtered"):
                try:
                    ports.add(int(p.get("port")))
                except (TypeError, ValueError):
                    pass
        else:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                pass
    return ports


def build_snapshot(
    arp_hosts: list[dict] | None = None,
    nmap_hosts: list[dict] | None = None,
    label: str = "baseline",
    meta: dict | None = None,
) -> dict[str, Any]:
    """Build a normalized baseline snapshot from ARP + nmap hosts."""
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    nmap_by_ip = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}

    assets: dict[str, dict] = {}
    for h in arp_hosts:
        key = _host_key(h)
        if not key:
            continue
        ip = h.get("ip") or ""
        nm = nmap_by_ip.get(ip) or {}
        ports = _ports_set(h) | _ports_set(nm)
        assets[key] = {
            "key": key,
            "ip": ip,
            "mac": (h.get("mac") or "").upper(),
            "hostname": h.get("hostname") or "",
            "vendor": h.get("vendor") or "",
            "role": h.get("role") or "unknown",
            "os_hint": h.get("os_hint") or "",
            "ports": sorted(ports),
            "tags": list(h.get("tags") or []),
        }

    for h in nmap_hosts:
        ip = h.get("ip") or ""
        if not ip:
            continue
        key = f"ip:{ip}"
        # Prefer MAC key if already present via ARP
        for a in assets.values():
            if a.get("ip") == ip:
                key = a["key"]
                break
        if key not in assets:
            assets[key] = {
                "key": key,
                "ip": ip,
                "mac": (h.get("mac") or "").upper(),
                "hostname": (h.get("hostnames") or [""])[0] if h.get("hostnames") else "",
                "vendor": h.get("vendor") or "",
                "role": "unknown",
                "os_hint": "",
                "ports": sorted(_ports_set(h)),
                "tags": [],
            }
        else:
            assets[key]["ports"] = sorted(set(assets[key]["ports"]) | _ports_set(h))

    now = datetime.now().isoformat(timespec="seconds")
    body = {
        "label": label,
        "created": now,
        "meta": meta or {},
        "asset_count": len(assets),
        "assets": assets,
    }
    raw = json.dumps(body, sort_keys=True, default=str)
    body["fingerprint"] = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return body


def diff_baseline(baseline: dict, current: dict) -> dict[str, Any]:
    """
    Diff two snapshots.
    Returns appeared / disappeared / changed (ip, hostname, vendor, role, ports).
    """
    base_assets = baseline.get("assets") or {}
    cur_assets = current.get("assets") or {}
    base_keys = set(base_assets.keys())
    cur_keys = set(cur_assets.keys())

    appeared = []
    for k in sorted(cur_keys - base_keys):
        a = cur_assets[k]
        appeared.append({"key": k, "ip": a.get("ip"), "mac": a.get("mac"), "hostname": a.get("hostname")})

    disappeared = []
    for k in sorted(base_keys - cur_keys):
        a = base_assets[k]
        disappeared.append({"key": k, "ip": a.get("ip"), "mac": a.get("mac"), "hostname": a.get("hostname")})

    changed = []
    for k in sorted(base_keys & cur_keys):
        b, c = base_assets[k], cur_assets[k]
        deltas: dict[str, Any] = {}
        for field in ("ip", "hostname", "vendor", "role"):
            if (b.get(field) or "") != (c.get(field) or ""):
                deltas[field] = {"from": b.get(field), "to": c.get(field)}
        bp, cp = set(b.get("ports") or []), set(c.get("ports") or [])
        if bp != cp:
            deltas["ports"] = {
                "opened": sorted(cp - bp),
                "closed": sorted(bp - cp),
                "from": sorted(bp),
                "to": sorted(cp),
            }
        if deltas:
            changed.append({
                "key": k,
                "ip": c.get("ip") or b.get("ip"),
                "mac": c.get("mac") or b.get("mac"),
                "hostname": c.get("hostname") or b.get("hostname"),
                "deltas": deltas,
            })

    summary = {
        "appeared": len(appeared),
        "disappeared": len(disappeared),
        "changed": len(changed),
        "baseline_assets": len(base_keys),
        "current_assets": len(cur_keys),
        "has_drift": bool(appeared or disappeared or changed),
    }
    return {
        "ok": True,
        "baseline_label": baseline.get("label"),
        "baseline_created": baseline.get("created"),
        "baseline_fp": baseline.get("fingerprint"),
        "current_created": current.get("created"),
        "current_fp": current.get("fingerprint"),
        "summary": summary,
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
    }


def severity_for_drift(diff: dict) -> str:
    """Heuristic severity for Hub alerts."""
    s = diff.get("summary") or {}
    if not s.get("has_drift"):
        return "info"
    # New open high-risk ports elevate severity
    critical_ports = {23, 445, 3389, 5900, 1433, 2375, 6379, 9200}
    for ch in diff.get("changed") or []:
        opened = set((ch.get("deltas") or {}).get("ports", {}).get("opened") or [])
        if opened & critical_ports:
            return "critical"
    if s.get("appeared", 0) >= 3 or s.get("changed", 0) >= 5:
        return "high"
    if s.get("appeared") or s.get("disappeared") or s.get("changed"):
        return "medium"
    return "info"
