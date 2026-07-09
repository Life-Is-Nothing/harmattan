"""
HARMATTAN — Nmap integration with safe args, robust XML parsing, duration tracking.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Callable, Optional

from core.config import NMAP_TIMEOUT
from core.logging_setup import get_logger
from core.validation import ValidationError, sanitize_nmap_custom_args, validate_target

log = get_logger("harmattan.nmap")

SCAN_PROFILES = {
    "quick": {
        "args": ["-T4", "-F"],
        "label": "Rapide (top 100)",
        "eta": "30s–2min",
        "desc": "Top 100 ports TCP, timing agressif",
    },
    "full": {
        "args": ["-T4", "-p-"],
        "label": "Tous les ports",
        "eta": "5–30min",
        "desc": "65535 ports TCP",
    },
    "service": {
        "args": ["-T4", "-sV", "-sC"],
        "label": "Services + versions",
        "eta": "2–10min",
        "desc": "Détection versions + scripts par défaut",
    },
    "os": {
        "args": ["-T4", "-O", "-sV"],
        "label": "Détection OS",
        "eta": "2–8min",
        "desc": "OS fingerprint + versions (root recommandé)",
    },
    "stealth": {
        "args": ["-T2", "-sS"],
        "label": "Discret SYN",
        "eta": "2–15min",
        "desc": "SYN scan lent (root requis)",
    },
    "udp": {
        "args": ["-T4", "-sU", "--top-ports", "50"],
        "label": "UDP top 50",
        "eta": "5–20min",
        "desc": "Top 50 ports UDP",
    },
    "vuln": {
        "args": ["-T4", "-sV", "--script", "vuln"],
        "label": "Scripts vuln",
        "eta": "5–20min",
        "desc": "NSE vuln + versions",
    },
    "banner": {
        "args": ["-T4", "-sV", "--script", "banner"],
        "label": "Banner grab NSE",
        "eta": "1–5min",
        "desc": "Bannières de services",
    },
    "vulners": {
        "args": ["-T4", "-sV", "--script", "vulners"],
        "label": "Vulners CVE",
        "eta": "2–10min",
        "desc": "CVE via script vulners",
    },
    "default_creds": {
        "args": ["-T4", "-sV", "--script", "http-default-accounts,ssh-auth-methods"],
        "label": "Default accounts",
        "eta": "2–8min",
        "desc": "Comptes par défaut HTTP + méthodes SSH",
    },
}


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def list_profiles() -> list[dict]:
    return [
        {"id": k, "label": v["label"], "eta": v["eta"], "desc": v["desc"]}
        for k, v in SCAN_PROFILES.items()
    ]


def run_scan(
    target: str,
    profile: str = "quick",
    custom_args: str = "",
    progress: Optional[Callable[[int, str], None]] = None,
) -> dict:
    started = datetime.now().isoformat()
    t0 = time.time()

    try:
        target = validate_target(target)
    except ValidationError as e:
        return {"error": e.code, "message": e.message, "hosts": []}

    if not nmap_available():
        return {
            "error": "nmap_missing",
            "message": "nmap n'est pas installé. Lancez: sudo apt install nmap",
            "hosts": [],
        }

    if profile not in SCAN_PROFILES:
        profile = "quick"

    args = list(SCAN_PROFILES[profile]["args"])
    try:
        args += sanitize_nmap_custom_args(custom_args)
    except ValidationError as e:
        return {"error": e.code, "message": e.message, "hosts": []}

    cmd = ["nmap", "-oX", "-"] + args + [target]
    log.info("nmap start profile=%s target=%s cmd=%s", profile, target, " ".join(cmd))

    if progress:
        progress(10, f"nmap {profile} → {target}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
        )
        if result.returncode != 0 and not result.stdout:
            return {
                "error": "scan_failed",
                "message": (result.stderr or "nmap a échoué").strip()[:500],
                "hosts": [],
            }

        if progress:
            progress(80, "Parsing résultats nmap…")

        parsed = _parse_nmap_xml(result.stdout, started, profile, target)
        parsed["duration_s"] = round(time.time() - t0, 2)
        parsed["command"] = " ".join(cmd)
        if progress:
            progress(100, "Scan nmap terminé")
        return parsed
    except subprocess.TimeoutExpired:
        return {
            "error": "timeout",
            "message": f"Le scan a dépassé le délai limite ({NMAP_TIMEOUT}s).",
            "hosts": [],
        }
    except Exception as e:
        log.exception("nmap failed")
        return {"error": "scan_failed", "message": str(e), "hosts": []}


def _addr_ipv4(host_el) -> Optional[str]:
    for a in host_el.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            return a.get("addr")
    # fallback
    addr_el = host_el.find("address")
    if addr_el is not None and addr_el.get("addrtype") != "mac":
        return addr_el.get("addr")
    return None


def _parse_nmap_xml(xml_data: str, started: str, profile: str, target: str) -> dict:
    hosts = []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"error": "parse_failed", "message": str(e), "hosts": []}

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip = _addr_ipv4(host_el) or "?"
        mac = None
        vendor = None
        for a in host_el.findall("address"):
            if a.get("addrtype") == "mac":
                mac = a.get("addr")
                vendor = a.get("vendor")

        hostnames = [h.get("name") for h in host_el.findall("hostnames/hostname") if h.get("name")]

        os_matches = []
        os_el = host_el.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                os_matches.append({"name": m.get("name"), "accuracy": m.get("accuracy")})

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                if state_el is None:
                    continue
                service_el = p.find("service")
                scripts = []
                for script in p.findall("script"):
                    scripts.append({
                        "id": script.get("id"),
                        "output": (script.get("output") or "").strip()[:2000],
                    })
                ports.append({
                    "port": p.get("portid"),
                    "protocol": p.get("protocol"),
                    "state": state_el.get("state"),
                    "service": service_el.get("name") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                    "scripts": scripts,
                })

        hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostnames": hostnames,
            "os_matches": os_matches,
            "ports": ports,
        })

    return {
        "target": target,
        "profile": profile,
        "started": started,
        "count": len(hosts),
        "hosts": hosts,
    }
