"""
HARMATTAN — OT/ICS Discovery module.
Industrial control systems protocol probes.
"""
from __future__ import annotations
import socket
from typing import List, Dict, Optional
from core.logging_setup import get_logger

log = get_logger("harmattan.ot")

# Basic probes for common industrial protocols
OT_PROTOCOLS = [
    {
        "id": "modbus",
        "name": "Modbus TCP",
        "port": 502,
        "transport": "tcp",
        "probe": b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"  # Read Coils
    },
    {
        "id": "s7comm",
        "name": "S7comm (Siemens)",
        "port": 102,
        "transport": "tcp",
        "probe": b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a" # COTP Connection Request
    },
    {
        "id": "bacnet",
        "name": "BACnet",
        "port": 47808,
        "transport": "udp",
        "probe": b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08" # Who-Is
    },
    {
        "id": "enip",
        "name": "EtherNet/IP",
        "port": 44818,
        "transport": "tcp",
        "probe": b"\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # List Services
    },
    {
        "id": "fox",
        "name": "Niagara Fox",
        "port": 1911,
        "transport": "tcp",
        "probe": b"fox:\r\n"
    },
]


def probe_host(ip: str, timeout: float = 1.0) -> List[Dict]:
    """Check for OT protocols on a single host."""
    results = []
    for proto in OT_PROTOCOLS:
        try:
            if proto["transport"] == "tcp":
                with socket.create_connection((ip, proto["port"]), timeout=timeout) as s:
                    if proto.get("probe"):
                        s.sendall(proto["probe"])
                        # Read small response to confirm it's not just a generic port open
                        s.recv(4)
                    results.append({
                        "id": proto["id"],
                        "name": proto["name"],
                        "port": proto["port"],
                        "transport": "tcp"
                    })
            elif proto["transport"] == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(proto["probe"], (ip, proto["port"]))
                    data, _ = s.recvfrom(4)
                    if data:
                        results.append({
                            "id": proto["id"],
                            "name": proto["name"],
                            "port": proto["port"],
                            "transport": "udp"
                        })
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return results


def scan_hosts(hosts: List[Dict], max_hosts: int = 50) -> Dict:
    """Scan a list of hosts for OT protocols."""
    log.info(f"Scanning {min(len(hosts), max_hosts)} hosts for OT protocols")
    found = []
    for host in hosts[:max_hosts]:
        ip = host.get("ip")
        if not ip:
            continue
        ot_data = probe_host(ip)
        if ot_data:
            found.append({
                "ip": ip,
                "mac": host.get("mac"),
                "vendor": host.get("vendor"),
                "hostname": host.get("hostname"),
                "protocols": ot_data
            })
    return {
        "count": len(found),
        "hosts": found,
        "timestamp": datetime.now().isoformat()
    }
