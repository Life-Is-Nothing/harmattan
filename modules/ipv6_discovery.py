"""
HARMATTAN — IPv6 Discovery module.
Uses ICMPv6 Echo Request to All-Nodes Multicast and Neighbor Discovery.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

from core.logging_setup import get_logger
from modules import fingerprinting

log = get_logger("harmattan.ipv6")

try:
    from scapy.all import Ether, IPv6, ICMPv6EchoRequest, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def ipv6_scan(iface: Optional[str] = None, timeout: float = 3.0) -> dict:
    """
    Perform an IPv6 discovery by sending an ICMPv6 Echo Request to ff02::1.
    """
    if not SCAPY_AVAILABLE:
        return {
            "error": "scapy_missing",
            "message": "Scapy n'est pas installé.",
            "hosts": [],
        }

    log.info(f"Starting IPv6 multicast discovery on {iface or 'default'}")

    hosts = []
    try:
        conf.verb = 0
        # ff02::1 is all-nodes link-local multicast
        # Mac 33:33:00:00:00:01 is for ff02::1
        pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()

        kwargs = {"timeout": timeout, "verbose": False}
        if iface:
            kwargs["iface"] = iface

        ans, _ = srp(pkt, **kwargs)

        seen = set()
        for _, r in ans:
            ipv6_addr = r[IPv6].src
            mac = r[Ether].src
            if ipv6_addr not in seen:
                seen.add(ipv6_addr)
                hosts.append({
                    "ip": ipv6_addr,  # using 'ip' key for consistency with UI
                    "ipv6": ipv6_addr,
                    "mac": mac,
                    "vendor": fingerprinting.get_vendor(mac),
                    "status": "up",
                    "role": "unknown",
                    "os_hint": "ipv6-node"
                })
    except Exception as e:
        log.error(f"IPv6 scan error: {e}")
        return {"error": str(e), "hosts": []}

    return {
        "started": datetime.now().isoformat(),
        "hosts": hosts,
        "count": len(hosts)
    }
