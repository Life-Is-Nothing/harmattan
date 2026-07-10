"""
HARMATTAN — Device fingerprinting (hostname, TTL/OS, ports, SNMP, role, IoT).
"""
from __future__ import annotations

import csv
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from core.config import ENRICH_WORKERS, SNMP_COMMUNITIES
from core.logging_setup import get_logger

log = get_logger("harmattan.fp")

try:
    from scapy.all import ICMP, IP as ScapyIP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

TOPOLOGY_PROBE_PORTS = [
    80, 443, 22, 23, 53, 8080, 8443, 179, 161, 8291, 2601, 4786,
    445, 3389, 554, 9100, 631, 1883, 5000, 8000,
]

PC_VENDORS = [
    "intel", "dell", "lenovo", "hp", "hewlett", "acer", "gigabyte",
    "msi", "asrock", "asus", "supermicro", "fujitsu",
]
ANDROID_VENDORS = [
    "samsung", "xiaomi", "oneplus", "oppo", "realme", "motorola",
    "lg electronics", "sony mobile", "zte", "huawei", "honor",
    "vivo", "tecno", "infinix", "google", "pixel", "nothing",
    "fairphone", "meizu",
]
MOBILE_VENDORS = ANDROID_VENDORS + [
    "nokia",  # mixed
]
TV_VENDORS = [
    "roku", "tcl", "hisense", "vizio", "chromecast", "nvidia", "shield",
    "skyworth", "philips tv",
]
TV_HOST_HINTS = [
    "tv", "roku", "chromecast", "firestick", "smart-tv", "androidtv",
    "bravia", "webos", "tizen-tv", "mi-box", "shield",
]
SERVER_HINTS = ["server", "nas", "synology", "qnap", "proxmox", "esxi", "dell emc"]
IOT_VENDORS = [
    "espressif", "tuya", "shelly", "sonoff", "ring", "nest",
    "philips", "tp-link technologies", "amazon technologies",
    "google", "roku", "wyze",
]
PRINTER_VENDORS = ["brother", "canon", "epson", "xerox", "ricoh", "kyocera", "lexmark"]
CAMERA_HINTS = ["hikvision", "dahua", "axis", "reolink", "amcrest", "foscam", "ipc", "cam"]

_oui_db: dict[str, str] = {}
_vendor_cache: dict[str, str] = {}
_oui_loaded = False

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP (cam)",
    631: "IPP (print)",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9100: "JetDirect",
}


def _load_oui_db() -> None:
    global _oui_db, _oui_loaded
    if _oui_loaded:
        return
    db_path = os.path.join(os.path.dirname(__file__), "oui.csv")
    if not os.path.exists(db_path):
        _oui_loaded = True
        return
    try:
        with open(db_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                oui = (row.get("Assignment") or "").upper().strip()
                name = (row.get("Organization Name") or "").strip()
                if oui and name:
                    _oui_db[oui] = name
        log.info("OUI database loaded: %d entries", len(_oui_db))
    except Exception as e:
        log.warning("OUI load failed: %s", e)
    _oui_loaded = True


def get_vendor(mac: str) -> str:
    if not mac:
        return "Inconnu"
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    _load_oui_db()
    vendor = _oui_db.get(oui, "Inconnu")
    _vendor_cache[oui] = vendor
    return vendor


def _dns_hostname(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass
    return None


def _netbios_hostname(ip: str) -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            b"\x00\x00!\x00\x01"
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 72:
            name = data[57:72].decode("ascii", errors="ignore").strip()
            name = "".join(c for c in name if c.isprintable()).strip()
            if name:
                return name
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> str:
    for fn in (_dns_hostname, _netbios_hostname):
        name = fn(ip)
        if name:
            return name
    return ""


def probe_ttl(ip: str) -> Optional[int]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt = ScapyIP(dst=ip, ttl=64) / ICMP()
        reply = sr1(pkt, timeout=0.8, verbose=False)
        if reply and ICMP in reply:
            return reply[ScapyIP].ttl
    except Exception:
        pass
    return None


def ttl_to_os_hint(ttl: Optional[int]) -> str:
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "linux/macos"
    if ttl <= 128:
        return "windows"
    return "network_device"


def probe_open_ports(ip: str, ports: list[int] | None = None, timeout: float = 0.35) -> list[int]:
    ports = ports or TOPOLOGY_PROBE_PORTS
    open_ports = []

    def _check(port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ok = sock.connect_ex((ip, port)) == 0
            sock.close()
            return port if ok else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=min(12, len(ports))) as pool:
        for res in pool.map(_check, ports):
            if res is not None:
                open_ports.append(res)
    return sorted(open_ports)


def probe_snmp_sysdescr(ip: str) -> Optional[str]:
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
    for community_str in SNMP_COMMUNITIES:
        try:
            community = community_str.encode()
            request = (
                b"\x30\x29"
                b"\x02\x01\x00"
                b"\x04" + bytes([len(community)]) + community + b"\xa0\x1c"
                b"\x02\x04\x00\x00\x00\x01"
                b"\x02\x01\x00"
                b"\x02\x01\x00"
                b"\x30\x0e"
                b"\x30\x0c"
                b"\x06\x08" + oid + b"\x05\x00"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.8)
            sock.sendto(request, (ip, 161))
            data, _ = sock.recvfrom(1024)
            sock.close()
            if data and len(data) > 30:
                text = data[30:].decode("ascii", errors="ignore").strip()
                if text:
                    return text
        except Exception:
            continue
    return None


def infer_role(
    ip: str,
    vendor: str,
    hostname: str,
    ttl: Optional[int],
    open_ports: list[int],
    is_gateway: bool,
) -> str:
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    os_hint = ttl_to_os_hint(ttl)

    if is_gateway or h in ("router", "gateway", "_gateway", "default-gateway"):
        return "gateway"

    if any(k in v for k in CAMERA_HINTS) or any(k in h for k in CAMERA_HINTS) or 554 in open_ports:
        return "camera"
    if any(k in v for k in PRINTER_VENDORS) or any(k in h for k in ["printer", "print", "hp-"]) or 9100 in open_ports or 631 in open_ports:
        return "printer"
    if any(k in v for k in IOT_VENDORS) or 1883 in open_ports:
        return "iot"

    if any(k in v for k in ["cisco", "mikrotik", "ubiquiti", "juniper", "fortinet", "edgecore", "brocade", "h3c"]):
        return "router"
    if any(k in v for k in ["tp-link", "netgear", "dlink", "d-link", "linksys", "tenda", "zyxel", "aruba", "ruckus", "meraki", "cambium"]):
        return "ap"
    if any(k in h for k in ["router", "gw", "gateway", "firewall", "pfsense", "opnsense", "vyos", "mikrotik"]):
        return "router"
    if any(k in h for k in ["ap", "wifi", "wlan", "wireless", "access-point", "hotspot"]):
        return "ap"
    if any(k in h for k in ["switch", "sw-", "sw_"]):
        return "switch"

    if "raspberry" in v or "raspberry" in h:
        return "raspberry"
    if any(k in v for k in ["vmware", "virtualbox", "proxmox", "parallels", "qemu", "xen"]):
        return "vm"
    if any(k in h for k in SERVER_HINTS) or any(k in v for k in ["synology", "qnap", "supermicro"]):
        return "server"
    # Apple ecosystem (before TV — Apple TV stays apple or tv)
    if "apple" in v or any(k in h for k in ["iphone", "ipad", "macbook", "imac", "ipod", "airport"]):
        return "apple"
    if "appletv" in h or "apple-tv" in h:
        return "tv"

    # Android phones / tablets BEFORE generic TV (Samsung phones ≠ TV)
    android_host = any(
        k in h
        for k in [
            "android",
            "galaxy",
            "pixel",
            "redmi",
            "xiaomi",
            "huawei",
            "honor",
            "oppo",
            "oneplus",
            "realme",
            "sm-",
            "phone",
            "redmi",
        ]
    )
    android_vendor = any(k in v for k in ANDROID_VENDORS)
    # Samsung/LG phones: vendor alone + phone-like hostname or no TV hint
    if android_host or (
        android_vendor
        and not any(k in h for k in TV_HOST_HINTS)
        and "tv" not in h
    ):
        if "nest" not in h and "chromecast" not in h:
            return "android"

    if any(k in v for k in TV_VENDORS) or any(k in h for k in TV_HOST_HINTS):
        return "tv"

    if any(k in h for k in ["iphone", "phone", "mobile", "tablet"]):
        return "mobile"

    if os_hint == "network_device":
        return "ap" if any(p in open_ports for p in [80, 443, 8080]) else "router"

    if any(k in v for k in PC_VENDORS):
        return "pc"
    if any(k in h for k in ["desktop", "pc-", "-pc", "workstation", "laptop", "linux", "windows", "ubuntu", "debian"]):
        return "pc"
    if os_hint == "linux/macos" and 22 in open_ports:
        return "pc"
    if os_hint == "windows" and any(p in open_ports for p in [135, 139, 445]):
        return "pc"
    # many open service ports → server-ish
    if len(open_ports) >= 5 and any(p in open_ports for p in [22, 80, 443, 3306, 5432]):
        return "server"

    return "unknown"


def enrich_host(host: dict, known_gateway_ip: Optional[str] = None, light: bool = False) -> dict:
    ip = host["ip"]
    host["hostname"] = resolve_hostname(ip) or host.get("hostname") or ""
    host["vendor"] = get_vendor(host.get("mac", ""))

    if light:
        host.setdefault("ttl", None)
        host.setdefault("os_hint", "unknown")
        host.setdefault("open_ports", [])
        host.setdefault("sensitive", [])
        host.setdefault("snmp_desc", "")
        host["role"] = infer_role(
            ip, host["vendor"], host["hostname"], None, [], ip == known_gateway_ip
        )
        host["status"] = host.get("status", "up")
        return host

    ttl = probe_ttl(ip)
    host["ttl"] = ttl
    host["os_hint"] = ttl_to_os_hint(ttl)
    open_ports = probe_open_ports(ip)
    host["open_ports"] = open_ports
    host["sensitive"] = [
        {"port": p, "name": SENSITIVE_PORTS[p]}
        for p in open_ports if p in SENSITIVE_PORTS
    ]
    snmp = None
    if 161 in open_ports or (ttl is not None and ttl > 128):
        snmp = probe_snmp_sysdescr(ip)
    host["snmp_desc"] = snmp or ""
    vendor_for_role = (snmp + " " if snmp else "") + host["vendor"]
    host["role"] = infer_role(
        ip, vendor_for_role, host["hostname"], ttl, open_ports, ip == known_gateway_ip
    )
    host["status"] = host.get("status", "up")
    # L0p4Map-style default-credential device flags (lightweight, no banners here)
    try:
        from modules.default_creds import assess_host

        flags = assess_host(host)
        if flags:
            host["default_cred_flags"] = flags
    except Exception:
        pass
    return host


def enrich_hosts(
    hosts: list[dict],
    gateway: Optional[str] = None,
    workers: int = ENRICH_WORKERS,
    light: bool = False,
) -> list[dict]:
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(enrich_host, dict(h), gateway, light): h for h in hosts
        }
        results = []
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append(futures[fut])
    results.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".") if p.isdigit()))
    return results
