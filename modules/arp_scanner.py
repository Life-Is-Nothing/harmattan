"""
HARMATTAN — ARP Scanner + device enrichment.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Optional

from modules import fingerprinting, network_info
from core.logging_setup import get_logger
from core.validation import ValidationError, validate_cidr, validate_iface

log = get_logger("harmattan.arp")

SCAPY_AVAILABLE = False
SCAPY_ERROR: str | None = None

try:
    import os as _os

    # Prefer raw sockets (works with root / CAP_NET_RAW; avoids libpcap quirks)
    _os.environ.setdefault("SCAPY_USE_PCAP", "0")
    from scapy.all import ARP, Ether, conf, srp  # type: ignore

    try:
        conf.use_pcap = False
        conf.verb = 0
        # Scapy ≥2.5 renamed L3rawSocket → L3PacketSocket (raw PF_PACKET L3 socket,
        # already the default when libpcap is disabled). Keep it explicit but
        # version-agnostic instead of referencing the removed L3rawSocket name.
        try:
            from scapy.arch import L3PacketSocket as _RawL3
            conf.L3socket = _RawL3
        except Exception:
            pass
    except Exception as _cfg_err:
        log.warning("Scapy config soft-fail: %s", _cfg_err)
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_ERROR = f"import: {e}"
    SCAPY_AVAILABLE = False
except Exception as e:
    SCAPY_ERROR = str(e)
    log.error("Scapy configuration error: %s", e)
    SCAPY_AVAILABLE = False


def _arp_resolve_mac(ip: str) -> Optional[str]:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=1, retry=1, verbose=False)
        for _, reply in ans:
            return reply[Ether].src
    except Exception:
        pass
    return None


def arp_scan(
    subnet: str,
    timeout: float = 2.0,
    iface: Optional[str] = None,
    enrich: bool = True,
    light: bool = False,
    progress: Optional[Callable[[int, str], None]] = None,
) -> dict:
    started = datetime.now().isoformat()
    t0 = time.time()

    try:
        subnet = validate_cidr(subnet)
        iface = validate_iface(iface)
    except ValidationError as e:
        return {"error": e.code, "message": e.message, "hosts": []}

    if not SCAPY_AVAILABLE:
        return {
            "error": "scapy_missing",
            "message": "Scapy n'est pas installé.",
            "hosts": [],
        }

    if progress:
        progress(10, f"ARP broadcast {subnet}")

    try:
        conf.verb = 0
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        kwargs = {"timeout": timeout, "retry": 2, "inter": 0.01, "verbose": False}
        if iface:
            kwargs["iface"] = iface

        answered, _ = srp(packet, **kwargs)

        seen_macs: dict[str, str] = {}
        for _, received in answered:
            mac = received.hwsrc if hasattr(received, "hwsrc") else received[Ether].src
            ip = received.psrc if hasattr(received, "psrc") else received[ARP].psrc
            if mac not in seen_macs:
                seen_macs[mac] = ip

        gateway = network_info.get_default_gateway()
        if gateway and gateway not in seen_macs.values():
            gw_mac = _arp_resolve_mac(gateway)
            if gw_mac:
                seen_macs[gw_mac] = gateway

        if progress:
            progress(40, f"{len(seen_macs)} MAC — enrichment…")

        hosts = []
        for mac, ip in seen_macs.items():
            hosts.append({
                "ip": ip,
                "mac": mac,
                "vendor": fingerprinting.get_vendor(mac),
                "hostname": "",
                "status": "up",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "role": "unknown",
                "snmp_desc": "",
                "sensitive": [],
            })

        if enrich and hosts:
            hosts = fingerprinting.enrich_hosts(hosts, gateway=gateway, light=light)

        hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".") if p.isdigit()))

        roles: dict[str, int] = {}
        for h in hosts:
            roles[h.get("role", "unknown")] = roles.get(h.get("role", "unknown"), 0) + 1

        if progress:
            progress(100, f"{len(hosts)} hôte(s)")

        return {
            "subnet": subnet,
            "gateway": gateway,
            "started": started,
            "duration_s": round(time.time() - t0, 2),
            "count": len(hosts),
            "roles": roles,
            "hosts": hosts,
            "light": light,
        }
    except PermissionError:
        return {
            "error": "permission_denied",
            "message": "Le scan ARP nécessite les privilèges root (sudo).",
            "hosts": [],
        }
    except Exception as e:
        log.exception("ARP scan failed")
        return {"error": "scan_failed", "message": str(e), "hosts": []}
