"""
HARMATTAN — Network context (interfaces, gateway, SSID, subnet).
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import subprocess
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def get_interfaces() -> list:
    result = []
    seen = set()

    if PSUTIL_AVAILABLE:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            if iface not in stats or not stats[iface].isup:
                continue
            ip = None
            netmask = None
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
            if not ip or ip.startswith("127."):
                continue
            subnet = ""
            try:
                subnet = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
            except Exception:
                pass
            result.append({
                "name": iface,
                "ip": ip,
                "netmask": netmask or "",
                "subnet": subnet,
                "virtual": _is_virtual_iface(iface),
            })
            seen.add(iface)

    try:
        out = subprocess.check_output(["ip", "addr", "show"], stderr=subprocess.DEVNULL, text=True)
        current = None
        for line in out.splitlines():
            m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>", line)
            if m:
                current = m.group(1) if "UP" in m.group(2).split(",") else None
                continue
            if current and current not in seen:
                am = re.match(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if am:
                    ip = am.group(1)
                    if ip.startswith("127."):
                        continue
                    prefix = am.group(2)
                    subnet = str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
                    result.append({
                        "name": current,
                        "ip": ip,
                        "netmask": "",
                        "subnet": subnet,
                        "virtual": _is_virtual_iface(current),
                    })
                    seen.add(current)
    except Exception:
        pass

    return result


def get_default_gateway() -> Optional[str]:
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                if fields[1] == "00000000":
                    gw = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
                    if gw and not gw.startswith("0."):
                        return gw
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True
        )
        parts = out.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def _is_virtual_iface(name: str) -> bool:
    n = name.lower()
    return any(
        n.startswith(p)
        for p in ("docker", "br-", "veth", "virbr", "vmnet", "tun", "tap", "lo", "wg", "zt")
    )


def get_local_subnet(iface_name: Optional[str] = None) -> str:
    ifaces = get_interfaces()
    if iface_name:
        for i in ifaces:
            if i["name"] == iface_name and i.get("subnet"):
                return i["subnet"]
    for i in ifaces:
        if i.get("subnet") and not _is_virtual_iface(i["name"]):
            return i["subnet"]
    for i in ifaces:
        if i.get("subnet"):
            return i["subnet"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split(".")[:3]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"


def get_local_ip(iface_name: Optional[str] = None) -> Optional[str]:
    ifaces = get_interfaces()
    if iface_name:
        for i in ifaces:
            if i["name"] == iface_name:
                return i["ip"]
    for i in ifaces:
        if not _is_virtual_iface(i["name"]):
            return i["ip"]
    return ifaces[0]["ip"] if ifaces else None


def get_wifi_ssid(iface_name: Optional[str] = None) -> Optional[str]:
    candidates = []
    if iface_name:
        candidates.append(iface_name)
    candidates += [i["name"] for i in get_interfaces()]
    candidates = list(dict.fromkeys(candidates))

    for iface in candidates:
        if not iface.startswith("wl") and "wlan" not in iface:
            continue
        try:
            out = subprocess.check_output(
                ["iwgetid", "-r", iface], stderr=subprocess.DEVNULL, text=True
            ).strip()
            if out:
                return out
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "link"], stderr=subprocess.DEVNULL, text=True
            )
            for line in out.splitlines():
                if "SSID:" in line:
                    return line.split("SSID:", 1)[1].strip()
        except Exception:
            pass

    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1]
    except Exception:
        pass
    return None


def suggest_capture_iface() -> Optional[str]:
    """Meilleure interface pour capture live (physique, up, non virtuelle)."""
    ifaces = get_interfaces()
    # préférence wifi/eth physique
    preferred = []
    for i in ifaces:
        name = i.get("name") or ""
        if i.get("virtual"):
            continue
        score = 0
        if name.startswith("wl") or "wlan" in name:
            score += 30
        if name.startswith("en") or name.startswith("eth"):
            score += 25
        if i.get("ip"):
            score += 10
        preferred.append((score, name))
    preferred.sort(reverse=True)
    if preferred:
        return preferred[0][1]
    return ifaces[0]["name"] if ifaces else None


def snapshot(iface: Optional[str] = None) -> dict:
    ifaces = get_interfaces()
    gateway = get_default_gateway()
    subnet = get_local_subnet(iface)
    local_ip = get_local_ip(iface)
    ssid = get_wifi_ssid(iface)
    return {
        "interfaces": ifaces,
        "gateway": gateway,
        "subnet": subnet,
        "local_ip": local_ip,
        "ssid": ssid,
        "capture_iface": suggest_capture_iface(),
        "running_as_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
    }
