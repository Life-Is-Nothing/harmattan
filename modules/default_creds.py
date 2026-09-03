"""
HARMATTAN — L0p4Map-style default-credential device detection.
Banner / vendor / port heuristics (flag for manual verification only).
"""
from __future__ import annotations

import re
import socket
from typing import Optional

# Patterns that often ship with default credentials
DEFAULT_CRED_SIGNATURES = [
    {
        "id": "hp_ilo",
        "name": "HP iLO / iLO Remote Mgmt",
        "ports": [443, 17988, 22],
        "banner": re.compile(r"iLO|Integrated Lights-Out|Hewlett.?Packard.*iLO", re.I),
        "vendor": re.compile(r"hewlett|hp enterprise|ilo", re.I),
        "risk": "haute",
        "hint": "Vérifier mots de passe iLO par défaut (Administrator / …)",
    },
    {
        "id": "dell_idrac",
        "name": "Dell iDRAC",
        "ports": [443, 5900, 22],
        "banner": re.compile(r"iDRAC|Integrated Dell Remote", re.I),
        "vendor": re.compile(r"dell", re.I),
        "risk": "haute",
        "hint": "iDRAC souvent root/calvin ou credentials usine",
    },
    {
        "id": "supermicro_ipmi",
        "name": "Supermicro IPMI / BMC",
        "ports": [443, 623, 80],
        "banner": re.compile(r"ATEN|IPMI|Super\s*Micro|BMC", re.I),
        "vendor": re.compile(r"super.?micro|aten", re.I),
        "risk": "haute",
        "hint": "BMC/IPMI : changer ADMIN/ADMIN",
    },
    {
        "id": "zebra_printer",
        "name": "Zebra Printer",
        "ports": [9100, 80, 443],
        "banner": re.compile(r"Zebra|ZTC|ZPL", re.I),
        "vendor": re.compile(r"zebra", re.I),
        "risk": "moyenne",
        "hint": "Imprimantes Zebra souvent sans auth JetDirect 9100",
    },
    {
        "id": "sato_printer",
        "name": "SATO Printer",
        "ports": [9100, 80],
        "banner": re.compile(r"SATO", re.I),
        "vendor": re.compile(r"sato", re.I),
        "risk": "moyenne",
        "hint": "Vérifier interface web SATO",
    },
    {
        "id": "infoprint",
        "name": "InfoPrint / IBM Printer",
        "ports": [9100, 80, 631],
        "banner": re.compile(r"InfoPrint|Infoprint", re.I),
        "vendor": re.compile(r"infoprint|ricoh|ibm", re.I),
        "risk": "moyenne",
        "hint": "InfoPrint — audit web/admin",
    },
    {
        "id": "xport_lantronix",
        "name": "Lantronix XPort / serial-eth",
        "ports": [80, 23, 9999, 10001],
        "banner": re.compile(r"XPort|Lantronix|CoBox", re.I),
        "vendor": re.compile(r"lantronix", re.I),
        "risk": "haute",
        "hint": "XPort souvent telnet sans mdp ou default",
    },
    {
        "id": "hikvision",
        "name": "Hikvision camera/NVR",
        "ports": [80, 443, 8000, 554],
        "banner": re.compile(r"Hikvision|DVR|App-webs", re.I),
        "vendor": re.compile(r"hikvision|hangzhou", re.I),
        "risk": "critique",
        "hint": "Caméras : admin/12345 fréquent + CVE historiques",
    },
    {
        "id": "dahua",
        "name": "Dahua camera/NVR",
        "ports": [80, 443, 37777, 554],
        "banner": re.compile(r"Dahua|DH-", re.I),
        "vendor": re.compile(r"dahua|zhejiang", re.I),
        "risk": "critique",
        "hint": "Vérifier credentials usine Dahua",
    },
    {
        "id": "router_admin",
        "name": "SOHO router admin",
        "ports": [80, 443, 8080],
        "banner": re.compile(r"TP-LINK|NETGEAR|D-Link|Huawei HG|ZTE|RouterOS|MikroTik", re.I),
        "vendor": re.compile(r"tp-link|netgear|d-link|mikrotik|zte|huawei", re.I),
        "risk": "moyenne",
        "hint": "Interface admin — mdp usine possibles",
    },
]


def grab_banner(ip: str, port: int, timeout: float = 1.2) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        if port in (80, 8080, 8000):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
        elif port == 443:
            s.close()
            return ""
        else:
            # wait for banner
            pass
        data = s.recv(512)
        s.close()
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def assess_host(host: dict, deep: bool = False) -> list[dict]:
    """Return list of default-cred risk flags for one host.

    deep=True: probe banners (slower). Default uses vendor/hostname/ports only.
    """
    ip = host.get("ip") or ""
    vendor = host.get("vendor") or ""
    hostname = host.get("hostname") or ""
    snmp = host.get("snmp_desc") or ""
    ports = host.get("open_ports") or []
    if isinstance(ports, list) and ports and isinstance(ports[0], dict):
        ports = [int(p.get("port") or 0) for p in ports]
    ports = [int(p) for p in ports if p]
    blob = f"{vendor} {hostname} {snmp}"
    hits = []
    banners_cache: dict[int, str] = {}
    # only safe banner ports (avoid hanging on VNC/IPMI)
BANNER_OK = {80, 8080, 8000, 23, 21, 22, 9100, 9999, 10001}

def verify_active_auth(ip: str, port: int, protocol: str = "http", timeout: float = 2.0) -> Optional[str]:
    """
    Attempt a safe login with common default credentials (admin/admin, root/root).
    Focuses on HTTP Basic Auth for embedded devices.
    """
    import base64
    import urllib.request
    from urllib.error import HTTPError, URLError

    if protocol == "http":
        schemes = ["http", "https"] if port in (443, 8443) else ["http"]
        creds = [("admin", "admin"), ("root", "root"), ("admin", "password"), ("admin", "1234")]
        
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}/"
            for user, pwd in creds:
                try:
                    req = urllib.request.Request(url)
                    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    req.add_header("Authorization", f"Basic {auth}")
                    # Create a custom opener to avoid following redirects or handling auth automatically
                    with urllib.request.urlopen(req, timeout=timeout) as response:
                        if response.status == 200:
                            return f"{user}:{pwd}"
                except HTTPError as e:
                    if e.code == 401: continue
                    if e.code == 200: return f"{user}:{pwd}"
                except Exception:
                    continue
    return None


def assess_host(host: dict, deep: bool = False, active: bool = False) -> list[dict]:
    """Return list of default-cred risk flags for one host.

    deep=True: probe banners (slower).
    active=True: attempt lightweight login verification.
    """
    ip = host.get("ip") or ""
    vendor = host.get("vendor") or ""
    hostname = host.get("hostname") or ""
    snmp = host.get("snmp_desc") or ""
    ports = host.get("open_ports") or []
    if isinstance(ports, list) and ports and isinstance(ports[0], dict):
        ports = [int(p.get("port") or 0) for p in ports]
    ports = [int(p) for p in ports if p]
    blob = f"{vendor} {hostname} {snmp}"
    hits = []
    banners_cache: dict[int, str] = {}
    
    for sig in DEFAULT_CRED_SIGNATURES:
        score = 0
        evidence = []
        if sig["vendor"].search(blob):
            score += 2
            evidence.append("vendor/hostname/snmp")
        
        verified_creds = None
        for p in sig["ports"]:
            if p in ports:
                score += 1
                evidence.append(f"port:{p}")
                
                if deep and p in BANNER_OK and ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    if p not in banners_cache:
                        banners_cache[p] = grab_banner(ip, p, timeout=0.6)
                    ban = banners_cache.get(p) or ""
                    if ban and sig["banner"].search(ban):
                        score += 3
                        evidence.append(f"banner:{p}")
                
                if active and p in (80, 8080, 8000, 443) and not verified_creds:
                    res = verify_active_auth(ip, p)
                    if res:
                        verified_creds = res
                        score += 5
                        evidence.append(f"active_match:{res}")

        has_banner = any(e.startswith("banner") for e in evidence)
        has_active = any(e.startswith("active_match") for e in evidence)
        has_vendor = any(e.startswith("vendor") for e in evidence)
        has_port = any(e.startswith("port") for e in evidence)
        
        ok = has_active or has_banner or (has_vendor and has_port) or (has_vendor and score >= 4)
        if ok and score >= 2:
            hits.append(
                {
                    "id": sig["id"],
                    "name": sig["name"],
                    "risk": "critique" if has_active else sig["risk"],
                    "hint": f"CONFIRMÉ: {verified_creds}" if verified_creds else sig["hint"],
                    "evidence": evidence,
                    "score": score,
                }
            )
    return hits


def scan_hosts(hosts: list[dict], max_hosts: int = 40, deep: bool = True, active: bool = False) -> dict:
    results = []
    for h in hosts[:max_hosts]:
        flags = assess_host(h, deep=deep, active=active)
        if flags:
            results.append(
                {
                    "ip": h.get("ip"),
                    "mac": h.get("mac"),
                    "hostname": h.get("hostname"),
                    "vendor": h.get("vendor"),
                    "role": h.get("role"),
                    "flags": flags,
                    "max_risk": _max_risk([f["risk"] for f in flags]),
                }
            )
    return {
        "scanned": min(len(hosts), max_hosts),
        "flagged": len(results),
        "hosts": results,
        "disclaimer": "Heuristique — vérification manuelle obligatoire, pas d'exploitation.",
    }


def _max_risk(risks: list[str]) -> str:
    order = {"critique": 4, "haute": 3, "moyenne": 2, "faible": 1, "info": 0}
    return max(risks, key=lambda r: order.get(r, 0)) if risks else "info"
