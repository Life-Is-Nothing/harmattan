"""
HARMATTAN — Range cartography (L0p4Map-style).
Scan CIDR + group remote hosts by last traceroute hop (parent router).
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from modules import fingerprinting, network_info
from modules.tools import traceroute


def parse_targets(spec: str) -> list[str]:
    """Expand CIDR / range / single IP (capped)."""
    spec = (spec or "").strip()
    if not spec:
        return []
    # CIDR
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(h) for h in net.hosts()]
            return hosts[:512]
        except ValueError:
            return []
    # range a.b.c.d-e or a.b.c.d-a.b.c.e
    m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", spec)
    if m:
        base, a, b = m.group(1), int(m.group(2)), int(m.group(3))
        if a > b:
            a, b = b, a
        return [f"{base}{i}" for i in range(a, min(b, a + 255) + 1)]
    # single
    try:
        ipaddress.ip_address(spec)
        return [spec]
    except ValueError:
        return []


def ping_alive(ip: str, timeout: float = 0.6) -> bool:
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip],
            capture_output=True,
            timeout=timeout + 1.5,
        )
        return r.returncode == 0
    except Exception:
        return False


def last_hop(ip: str, max_hops: int = 12) -> Optional[str]:
    """Return penultimate hop before target (parent router), if any."""
    tr = traceroute(ip, max_hops=max_hops)
    hops = tr.get("hops") or []
    ips = []
    for h in hops:
        hip = h.get("ip") or h.get("host")
        if hip and hip not in ("*", "???"):
            # strip latency annotations
            hip = re.split(r"\s+", str(hip))[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", hip):
                ips.append(hip)
    if not ips:
        return None
    # if last hop is target, parent is previous
    if ips[-1] == ip and len(ips) >= 2:
        return ips[-2]
    if ips[-1] != ip:
        return ips[-1]
    return ips[-2] if len(ips) >= 2 else None


def map_range(
    target: str,
    iface: str | None = None,
    enrich: bool = True,
    progress: Optional[Callable] = None,
) -> dict:
    started = datetime.now().isoformat(timespec="seconds")
    targets = parse_targets(target)
    if not targets:
        return {"ok": False, "error": "bad_target", "hosts": [], "started": started}

    if progress:
        progress(5, f"Ping sweep {len(targets)} cibles…")

    alive = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futs = {pool.submit(ping_alive, ip): ip for ip in targets}
        for i, fut in enumerate(as_completed(futs)):
            ip = futs[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass
            if progress and i % 20 == 0:
                progress(5 + int(40 * i / max(1, len(targets))), f"Ping {i}/{len(targets)}")

    if progress:
        progress(50, f"{len(alive)} hôtes up — traceroute parents…")

    local_subnet = network_info.get_local_subnet()
    gateway = network_info.get_default_gateway()
    hosts = []
    parents: dict[str, str] = {}

    def _parent(ip: str) -> str:
        try:
            if local_subnet and ipaddress.ip_address(ip) in ipaddress.ip_network(local_subnet, strict=False):
                return gateway or "local"
        except Exception:
            pass
        hop = last_hop(ip)
        return hop or gateway or "unknown"

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(_parent, ip): ip for ip in alive}
        done = 0
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                parents[ip] = fut.result()
            except Exception:
                parents[ip] = gateway or "unknown"
            done += 1
            if progress and done % 5 == 0:
                progress(50 + int(30 * done / max(1, len(alive))), f"Trace {done}/{len(alive)}")

    for ip in alive:
        hosts.append(
            {
                "ip": ip,
                "mac": "",
                "parent": parents.get(ip),
                "status": "up",
                "via": "range_map",
            }
        )

    if enrich and hosts:
        if progress:
            progress(85, "Enrichissement fingerprint…")
        hosts = fingerprinting.enrich_hosts(hosts, gateway=gateway, light=False)

    # group summary
    by_parent: dict[str, list] = {}
    for h in hosts:
        by_parent.setdefault(h.get("parent") or "?", []).append(h.get("ip"))

    if progress:
        progress(100, "OK")

    return {
        "ok": True,
        "started": started,
        "finished": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "probed": len(targets),
        "alive": len(alive),
        "hosts": hosts,
        "by_parent": {k: len(v) for k, v in by_parent.items()},
        "parents": by_parent,
        "gateway": gateway,
        "local_subnet": local_subnet,
    }
