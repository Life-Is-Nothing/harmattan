"""Lightweight mDNS/SSDP discovery (best-effort, no extra deps required)."""
from __future__ import annotations

import socket
import struct
from datetime import datetime
from typing import Callable, Optional


def discover_mdns_ssdp(timeout: float = 2.5, progress: Optional[Callable] = None) -> dict:
    started = datetime.now().isoformat(timespec="seconds")
    if progress:
        progress(10, "mDNS probe…")
    mdns = _mdns_browse(timeout=timeout)
    if progress:
        progress(55, "SSDP probe…")
    ssdp = _ssdp_search(timeout=timeout)
    if progress:
        progress(100, "OK")
    return {
        "started": started,
        "mdns": mdns,
        "ssdp": ssdp,
        "count": len(mdns) + len(ssdp),
    }


def _mdns_browse(timeout: float = 2.0) -> list[dict]:
    """Send DNS-SD PTR query for _services._dns-sd._udp.local."""
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        # minimal mDNS query for PTR _services._dns-sd._udp.local
        qname = b"".join(
            bytes([len(p)]) + p.encode()
            for p in ["_services", "_dns-sd", "_udp", "local"]
        ) + b"\x00"
        # header + question
        pkt = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack("!HH", 12, 1)
        sock.sendto(pkt, ("224.0.0.251", 5353))
        end = datetime.now().timestamp() + timeout
        seen = set()
        while datetime.now().timestamp() < end:
            try:
                data, addr = sock.recvfrom(2048)
                key = (addr[0], data[:20])
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "ip": addr[0],
                    "port": addr[1],
                    "bytes": len(data),
                    "source": "mdns",
                })
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception as e:
        return [{"error": str(e)}]
    # unique by ip
    by_ip = {}
    for r in results:
        if "ip" in r:
            by_ip[r["ip"]] = r
    return list(by_ip.values())


def _ssdp_search(timeout: float = 2.0) -> list[dict]:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msg.encode(), ("239.255.255.250", 1900))
        end = datetime.now().timestamp() + timeout
        seen = set()
        while datetime.now().timestamp() < end:
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                server = _hdr(text, "SERVER")
                usn = _hdr(text, "USN")
                loc = _hdr(text, "LOCATION")
                st = _hdr(text, "ST")
                key = (addr[0], usn or loc or text[:40])
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "ip": addr[0],
                    "server": server,
                    "usn": usn,
                    "location": loc,
                    "st": st,
                    "source": "ssdp",
                })
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception as e:
        return [{"error": str(e)}]
    return results


def _hdr(text: str, name: str) -> str:
    for line in text.splitlines():
        if line.upper().startswith(name.upper() + ":"):
            return line.split(":", 1)[1].strip()
    return ""
