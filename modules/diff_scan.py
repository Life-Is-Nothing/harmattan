"""Compare two ARP discovery results (new / gone / changed hosts)."""
from __future__ import annotations


def diff_arp(old: dict | None, new: dict | None) -> dict:
    old = old or {}
    new = new or {}
    old_hosts = {h.get("ip"): h for h in (old.get("hosts") or []) if h.get("ip")}
    new_hosts = {h.get("ip"): h for h in (new.get("hosts") or []) if h.get("ip")}

    old_ips = set(old_hosts)
    new_ips = set(new_hosts)

    appeared = []
    for ip in sorted(new_ips - old_ips, key=_ipkey):
        h = new_hosts[ip]
        appeared.append({
            "ip": ip,
            "mac": h.get("mac"),
            "vendor": h.get("vendor"),
            "hostname": h.get("hostname"),
            "role": h.get("role"),
        })

    disappeared = []
    for ip in sorted(old_ips - new_ips, key=_ipkey):
        h = old_hosts[ip]
        disappeared.append({
            "ip": ip,
            "mac": h.get("mac"),
            "vendor": h.get("vendor"),
            "hostname": h.get("hostname"),
            "role": h.get("role"),
        })

    changed = []
    for ip in sorted(old_ips & new_ips, key=_ipkey):
        o, n = old_hosts[ip], new_hosts[ip]
        deltas = {}
        for field in ("mac", "hostname", "vendor", "role", "os_hint"):
            if (o.get(field) or "") != (n.get(field) or ""):
                deltas[field] = {"from": o.get(field), "to": n.get(field)}
        op = set(o.get("open_ports") or [])
        np = set(n.get("open_ports") or [])
        if op != np:
            deltas["open_ports"] = {
                "added": sorted(np - op),
                "removed": sorted(op - np),
            }
        if deltas:
            changed.append({"ip": ip, "changes": deltas})

    return {
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
        "summary": {
            "appeared": len(appeared),
            "disappeared": len(disappeared),
            "changed": len(changed),
            "old_count": len(old_ips),
            "new_count": len(new_ips),
        },
    }


def _ipkey(ip: str):
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return (999, 999, 999, 999)
