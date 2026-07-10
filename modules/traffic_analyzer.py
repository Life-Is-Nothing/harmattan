"""
HARMATTAN — Capture trafic type Wireshark.
Liste paquets · arbre de dissection · hex dump · filtre display.
"""
from __future__ import annotations

import csv
import io
import os
import re
import struct
import tempfile
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Optional

from core.config import TRAFFIC_BUFFER
from core.logging_setup import get_logger

log = get_logger("harmattan.traffic")

try:
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        DNSRR,
        Ether,
        ICMP,
        IP,
        IPv6,
        Raw,
        TCP,
        UDP,
        rdpcap,
        sniff,
        wrpcap,
    )

    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
    except Exception:
        HTTPRequest = HTTPResponse = None  # type: ignore
    try:
        from scapy.layers.dhcp import DHCP, BOOTP
    except Exception:
        DHCP = BOOTP = None  # type: ignore
    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
    except Exception:
        ICMPv6EchoRequest = ICMPv6EchoReply = None  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    wrpcap = None  # type: ignore
    rdpcap = None  # type: ignore


# Ports → protocol label (Wireshark-style)
PORT_PROTO = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "TLS",
    445: "SMB",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP",
    8443: "TLS",
}


def _hexdump(data: bytes, width: int = 16) -> list[dict]:
    """Lines: {offset, hex, ascii} like Wireshark bottom pane."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        # pad hex column
        hx = hx.ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({"offset": f"{i:04x}", "hex": hx, "ascii": asc})
    return lines


def _tcp_flags(flags: int) -> str:
    names = []
    mapping = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    for bit, name in mapping:
        if flags & bit:
            names.append(name)
    return ",".join(names) if names else str(flags)


def dissect_packet(pkt, no: int) -> dict[str, Any]:
    """Build Wireshark-like row + layers + hex."""
    raw = bytes(pkt) if pkt is not None else b""
    now = datetime.now()
    entry: dict[str, Any] = {
        "no": no,
        "time": now.strftime("%H:%M:%S.%f")[:-3],
        "epoch": now.timestamp(),
        "src": "—",
        "dst": "—",
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "length": len(raw),
        "info": "",
        "layers": [],
        "hex": _hexdump(raw[:2048]),
        "raw_len": len(raw),
    }

    layers = entry["layers"]
    info_parts = []

    # Ethernet
    if SCAPY_AVAILABLE and Ether in pkt:
        eth = pkt[Ether]
        layers.append(
            {
                "name": "Ethernet",
                "summary": f"{eth.src} → {eth.dst}",
                "fields": [
                    {"k": "src", "v": eth.src},
                    {"k": "dst", "v": eth.dst},
                    {"k": "type", "v": hex(int(eth.type)) if eth.type is not None else "—"},
                ],
            }
        )

    # ARP
    if SCAPY_AVAILABLE and ARP in pkt:
        arp = pkt[ARP]
        entry["protocol"] = "ARP"
        entry["src"] = arp.psrc or eth.src if Ether in pkt else arp.psrc
        entry["dst"] = arp.pdst
        op = "who-has" if int(arp.op) == 1 else "is-at" if int(arp.op) == 2 else str(arp.op)
        info_parts.append(f"{op} {arp.pdst}" if int(arp.op) == 1 else f"{op} {arp.psrc} is-at {arp.hwsrc}")
        layers.append(
            {
                "name": "ARP",
                "summary": op,
                "fields": [
                    {"k": "op", "v": op},
                    {"k": "psrc", "v": arp.psrc},
                    {"k": "pdst", "v": arp.pdst},
                    {"k": "hwsrc", "v": arp.hwsrc},
                    {"k": "hwdst", "v": arp.hwdst},
                ],
            }
        )
        entry["info"] = " ".join(info_parts)
        return entry

    # IP / IPv6
    ip_layer = None
    if SCAPY_AVAILABLE and IP in pkt:
        ip_layer = pkt[IP]
        entry["src"], entry["dst"] = ip_layer.src, ip_layer.dst
        layers.append(
            {
                "name": "Internet Protocol Version 4",
                "summary": f"{ip_layer.src} → {ip_layer.dst}",
                "fields": [
                    {"k": "src", "v": ip_layer.src},
                    {"k": "dst", "v": ip_layer.dst},
                    {"k": "ttl", "v": str(ip_layer.ttl)},
                    {"k": "proto", "v": str(ip_layer.proto)},
                    {"k": "len", "v": str(ip_layer.len)},
                    {"k": "id", "v": str(ip_layer.id)},
                ],
            }
        )
    elif SCAPY_AVAILABLE and IPv6 in pkt:
        ip_layer = pkt[IPv6]
        entry["src"], entry["dst"] = ip_layer.src, ip_layer.dst
        layers.append(
            {
                "name": "Internet Protocol Version 6",
                "summary": f"{ip_layer.src} → {ip_layer.dst}",
                "fields": [
                    {"k": "src", "v": ip_layer.src},
                    {"k": "dst", "v": ip_layer.dst},
                    {"k": "nh", "v": str(ip_layer.nh)},
                    {"k": "hlim", "v": str(ip_layer.hlim)},
                ],
            }
        )
    else:
        entry["protocol"] = getattr(pkt, "name", None) or pkt.__class__.__name__[:16]
        entry["info"] = entry["protocol"]
        layers.append({"name": entry["protocol"], "summary": "non-IP", "fields": []})
        return entry

    # ICMP
    if SCAPY_AVAILABLE and ICMP in pkt:
        icmp = pkt[ICMP]
        entry["protocol"] = "ICMP"
        t = int(icmp.type)
        type_name = {0: "Echo reply", 8: "Echo request", 3: "Dest unreachable", 11: "Time exceeded"}.get(t, f"type {t}")
        info_parts.append(type_name)
        layers.append(
            {
                "name": "ICMP",
                "summary": type_name,
                "fields": [
                    {"k": "type", "v": str(t)},
                    {"k": "code", "v": str(icmp.code)},
                ],
            }
        )
        entry["info"] = " ".join(info_parts)
        return entry

    # TCP
    if SCAPY_AVAILABLE and TCP in pkt:
        tcp = pkt[TCP]
        entry["sport"] = int(tcp.sport)
        entry["dport"] = int(tcp.dport)
        flags = _tcp_flags(int(tcp.flags))
        app = PORT_PROTO.get(entry["dport"]) or PORT_PROTO.get(entry["sport"]) or "TCP"
        entry["protocol"] = app if app not in ("HTTP", "TLS", "SSH", "SMB", "RDP") else app
        if app == "TCP":
            entry["protocol"] = "TCP"
        info_parts.append(f"{entry['sport']} → {entry['dport']} [{flags}]")
        info_parts.append(f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}")
        layers.append(
            {
                "name": "Transmission Control Protocol",
                "summary": f"{entry['sport']} → {entry['dport']} [{flags}]",
                "fields": [
                    {"k": "srcport", "v": str(entry["sport"])},
                    {"k": "dstport", "v": str(entry["dport"])},
                    {"k": "flags", "v": flags},
                    {"k": "seq", "v": str(tcp.seq)},
                    {"k": "ack", "v": str(tcp.ack)},
                    {"k": "window", "v": str(tcp.window)},
                ],
            }
        )
        # HTTP
        if HTTPRequest is not None and HTTPRequest in pkt:
            h = pkt[HTTPRequest]
            method = (h.Method or b"").decode(errors="ignore")
            path = (h.Path or b"").decode(errors="ignore")
            host = (h.Host or b"").decode(errors="ignore") if hasattr(h, "Host") else ""
            entry["protocol"] = "HTTP"
            info_parts = [f"{method} {path}", f"Host: {host}" if host else ""]
            layers.append(
                {
                    "name": "Hypertext Transfer Protocol",
                    "summary": f"{method} {path}",
                    "fields": [
                        {"k": "method", "v": method},
                        {"k": "path", "v": path},
                        {"k": "host", "v": host},
                    ],
                }
            )
        elif HTTPResponse is not None and HTTPResponse in pkt:
            h = pkt[HTTPResponse]
            code = (h.Status_Code or b"").decode(errors="ignore")
            entry["protocol"] = "HTTP"
            info_parts = [f"HTTP {code}"]
            layers.append(
                {
                    "name": "Hypertext Transfer Protocol",
                    "summary": f"Response {code}",
                    "fields": [{"k": "status", "v": code}],
                }
            )
        elif entry["dport"] == 443 or entry["sport"] == 443:
            entry["protocol"] = "TLS"
            # TLS ClientHello heuristic
            payload = bytes(tcp.payload) if tcp.payload else b""
            if len(payload) > 5 and payload[0] == 0x16:
                info_parts.append("Client Hello" if len(payload) > 5 and payload[5:6] == b"\x01" or (len(payload) > 5 and payload[0] == 0x16) else "Handshake")
                if len(payload) > 5:
                    info_parts[-1] = "TLS Handshake"
            else:
                info_parts.append("Application Data" if payload else "TCP segment")
            layers.append(
                {
                    "name": "Transport Layer Security",
                    "summary": info_parts[-1] if info_parts else "TLS",
                    "fields": [{"k": "payload_len", "v": str(len(payload))}],
                }
            )
        elif Raw in pkt:
            raw_pay = bytes(pkt[Raw].load)[:200]
            # HTTP plaintext fallback
            if raw_pay.startswith((b"GET ", b"POST ", b"HEAD ", b"HTTP/")):
                entry["protocol"] = "HTTP"
                line = raw_pay.split(b"\r\n")[0].decode(errors="ignore")
                info_parts = [line]
                layers.append(
                    {
                        "name": "Hypertext Transfer Protocol",
                        "summary": line[:80],
                        "fields": [{"k": "request_line", "v": line[:200]}],
                    }
                )
            else:
                layers.append(
                    {
                        "name": "Data",
                        "summary": f"{len(bytes(pkt[Raw].load))} bytes",
                        "fields": [{"k": "len", "v": str(len(bytes(pkt[Raw].load)))}],
                    }
                )

        entry["info"] = " ".join(p for p in info_parts if p)
        return entry

    # UDP
    if SCAPY_AVAILABLE and UDP in pkt:
        udp = pkt[UDP]
        entry["sport"] = int(udp.sport)
        entry["dport"] = int(udp.dport)
        app = PORT_PROTO.get(entry["dport"]) or PORT_PROTO.get(entry["sport"]) or "UDP"
        entry["protocol"] = app if app != "TCP" else "UDP"
        info_parts.append(f"{entry['sport']} → {entry['dport']}")
        layers.append(
            {
                "name": "User Datagram Protocol",
                "summary": f"{entry['sport']} → {entry['dport']}",
                "fields": [
                    {"k": "srcport", "v": str(entry["sport"])},
                    {"k": "dstport", "v": str(entry["dport"])},
                    {"k": "len", "v": str(udp.len)},
                ],
            }
        )

        # DNS
        if DNS in pkt:
            dns = pkt[DNS]
            entry["protocol"] = "DNS"
            qname = ""
            if dns.qdcount and DNSQR in pkt:
                try:
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = str(getattr(pkt[DNSQR], "qname", ""))
            if dns.qr == 0:
                info_parts = [f"Standard query 0x{dns.id:04x}", f"A {qname}" if qname else "query"]
            else:
                ans = ""
                if dns.ancount and DNSRR in pkt:
                    try:
                        ans = str(pkt[DNSRR].rdata)
                    except Exception:
                        ans = f"{dns.ancount} ans"
                info_parts = [f"Standard query response 0x{dns.id:04x}", qname, ans]
            layers.append(
                {
                    "name": "Domain Name System",
                    "summary": " ".join(info_parts),
                    "fields": [
                        {"k": "id", "v": f"0x{dns.id:04x}"},
                        {"k": "qr", "v": "response" if dns.qr else "query"},
                        {"k": "qname", "v": qname},
                        {"k": "ancount", "v": str(dns.ancount)},
                    ],
                }
            )
        elif DHCP is not None and DHCP in pkt:
            entry["protocol"] = "DHCP"
            opts = {}
            try:
                for o in pkt[DHCP].options:
                    if isinstance(o, tuple) and len(o) >= 2:
                        opts[str(o[0])] = str(o[1])
            except Exception:
                pass
            msg = opts.get("message-type", "DHCP")
            info_parts = [f"DHCP {msg}", opts.get("requested_addr", "")]
            layers.append(
                {
                    "name": "Dynamic Host Configuration Protocol",
                    "summary": f"DHCP {msg}",
                    "fields": [{"k": k, "v": v} for k, v in list(opts.items())[:12]],
                }
            )
        elif entry["dport"] == 53 or entry["sport"] == 53:
            entry["protocol"] = "DNS"
            info_parts.append("DNS")
        elif Raw in pkt:
            layers.append(
                {
                    "name": "Data",
                    "summary": f"{len(bytes(pkt[Raw].load))} bytes",
                    "fields": [{"k": "len", "v": str(len(bytes(pkt[Raw].load)))}],
                }
            )

        entry["info"] = " ".join(p for p in info_parts if p)
        return entry

    entry["protocol"] = "IP"
    entry["info"] = f"{entry['src']} → {entry['dst']}"
    return entry


def match_display_filter(pkt_entry: dict, filt: str) -> bool:
    """Simple Wireshark-like display filter."""
    if not filt or not filt.strip():
        return True
    f = filt.strip().lower()
    proto = (pkt_entry.get("protocol") or "").lower()
    src = (pkt_entry.get("src") or "").lower()
    dst = (pkt_entry.get("dst") or "").lower()
    info = (pkt_entry.get("info") or "").lower()
    sport = str(pkt_entry.get("sport") or "")
    dport = str(pkt_entry.get("dport") or "")

    # compound && 
    if "&&" in f or " and " in f:
        parts = re.split(r"\s*&&\s*|\s+and\s+", f)
        return all(match_display_filter(pkt_entry, p) for p in parts if p.strip())
    if "||" in f or " or " in f:
        parts = re.split(r"\s*\|\|\s*|\s+or\s+", f)
        return any(match_display_filter(pkt_entry, p) for p in parts if p.strip())

    # protocol only (app protocols map back to L4)
    TCP_FAMILY = {"tcp", "http", "tls", "ssh", "smb", "rdp", "ftp", "smtp", "mysql"}
    UDP_FAMILY = {"udp", "dns", "dhcp", "ntp", "snmp", "mqtt"}
    if f == "tcp":
        return proto in TCP_FAMILY or "tcp" in proto
    if f == "udp":
        return proto in UDP_FAMILY or "udp" in proto
    if f in ("dns", "http", "tls", "arp", "icmp", "dhcp", "ssh", "smb"):
        return proto == f or f in proto

    # ip.addr == x / ip.src / ip.dst
    m = re.match(r"ip\.addr\s*==\s*([^\s]+)", f)
    if m:
        ip = m.group(1).lower()
        return ip == src or ip == dst
    m = re.match(r"ip\.src\s*==\s*([^\s]+)", f)
    if m:
        return m.group(1).lower() == src
    m = re.match(r"ip\.dst\s*==\s*([^\s]+)", f)
    if m:
        return m.group(1).lower() == dst

    # tcp.port / udp.port
    m = re.match(r"(?:tcp|udp)\.port\s*==\s*(\d+)", f)
    if m:
        p = m.group(1)
        return sport == p or dport == p
    m = re.match(r"(?:tcp|udp)\.(?:src|dst)port\s*==\s*(\d+)", f)
    if m:
        return m.group(1) in (sport, dport)

    # contains
    m = re.match(r"frame contains\s+(.+)", f)
    if m:
        needle = m.group(1).strip().strip("\"'")
        return needle in info or needle in src or needle in dst

    # free text: match anywhere
    blob = f"{proto} {src} {dst} {sport} {dport} {info}"
    return f in blob


class TrafficCapture:
    """Capture type Wireshark : buffer de paquets disséqués + raw scapy."""

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = ""):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.packets: deque = deque(maxlen=TRAFFIC_BUFFER)
        self._raw_packets: deque = deque(maxlen=min(TRAFFIC_BUFFER, 3000))
        self._by_no: dict[int, dict] = {}
        self.stats: dict = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self._stats_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.error: Optional[str] = None
        self.started_at: Optional[str] = None
        self.bytes_total = 0
        self.packets_total = 0
        self._seq = 0
        self.display_filter = ""

    def _handle_packet(self, pkt) -> None:
        with self._stats_lock:
            self._seq += 1
            no = self._seq
        try:
            entry = dissect_packet(pkt, no)
        except Exception as e:
            log.debug("dissect error: %s", e)
            entry = {
                "no": no,
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": "—",
                "dst": "—",
                "protocol": "ERR",
                "sport": None,
                "dport": None,
                "length": len(pkt) if pkt else 0,
                "info": str(e)[:80],
                "layers": [],
                "hex": [],
                "raw_len": 0,
            }

        src, dst = entry["src"], entry["dst"]
        proto = entry["protocol"]
        dport = entry.get("dport") or 0
        length = entry["length"]

        with self._stats_lock:
            self.packets.append(entry)
            self._raw_packets.append(pkt)
            self._by_no[no] = entry
            # prune index for old packets
            if len(self._by_no) > TRAFFIC_BUFFER + 100:
                oldest = min(self._by_no.keys())
                for k in list(self._by_no.keys()):
                    if k < oldest + 200:
                        del self._by_no[k]
            self.packets_total += 1
            self.bytes_total += length
            key = (src, dst, proto, dport)
            self.stats[key]["packets"] += 1
            self.stats[key]["bytes"] += length
            if len(self.stats) > 2000:
                for k, _ in sorted(self.stats.items(), key=lambda x: x[1]["bytes"])[:500]:
                    del self.stats[k]

    def _run(self) -> None:
        if not SCAPY_AVAILABLE:
            self.error = "Scapy n'est pas installé."
            self.running = False
            return
        try:
            kwargs = {
                "prn": self._handle_packet,
                "store": False,
                "stop_filter": lambda p: self._stop_event.is_set(),
            }
            if self.iface:
                kwargs["iface"] = self.iface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            sniff(**kwargs)
        except PermissionError:
            self.error = "La capture de trafic nécessite les privilèges root (sudo)."
            log.warning(self.error)
        except Exception as e:
            self.error = str(e)
            log.exception("capture error")
        finally:
            self.running = False

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self.running = True
        self.error = None
        self.started_at = datetime.now().isoformat(timespec="seconds")
        self._thread = threading.Thread(target=self._run, daemon=True, name="traffic-capture")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.running = False

    def capture_oneshot(self, seconds: int = 10) -> dict:
        if not SCAPY_AVAILABLE:
            self.error = "Scapy n'est pas installé."
            return self.snapshot()
        seconds = max(1, min(int(seconds), 60))
        self.error = None
        self.running = True
        self.started_at = datetime.now().isoformat(timespec="seconds")
        try:
            kwargs = {
                "prn": self._handle_packet,
                "store": False,
                "timeout": seconds,
            }
            if self.iface:
                kwargs["iface"] = self.iface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            sniff(**kwargs)
        except PermissionError:
            self.error = (
                "Privilèges insuffisants. Relance HARMATTAN avec sudo "
                "ou : sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)"
            )
            log.warning(self.error)
        except Exception as e:
            self.error = str(e)
            log.exception("oneshot capture error")
        finally:
            self.running = False
        return self.snapshot()

    def list_packets(
        self,
        offset: int = 0,
        limit: int = 200,
        display_filter: str = "",
        include_detail: bool = False,
    ) -> dict:
        with self._stats_lock:
            all_pkts = list(self.packets)
        filt = display_filter or self.display_filter
        if filt:
            filtered = [p for p in all_pkts if match_display_filter(p, filt)]
        else:
            filtered = all_pkts
        total = len(filtered)
        # newest at bottom like Wireshark default — show from offset
        slice_ = filtered[offset : offset + limit]
        rows = []
        for p in slice_:
            row = {
                "no": p["no"],
                "time": p["time"],
                "src": p["src"],
                "dst": p["dst"],
                "protocol": p["protocol"],
                "sport": p.get("sport"),
                "dport": p.get("dport"),
                "length": p["length"],
                "info": p.get("info") or "",
            }
            if include_detail:
                row["layers"] = p.get("layers") or []
                row["hex"] = p.get("hex") or []
            rows.append(row)
        return {
            "total": total,
            "buffer_total": len(all_pkts),
            "offset": offset,
            "limit": limit,
            "filter": filt,
            "packets": rows,
            "running": self.running,
            "error": self.error,
            "bytes_total": self.bytes_total,
            "packets_total": self.packets_total,
        }

    def get_packet(self, no: int) -> Optional[dict]:
        with self._stats_lock:
            p = self._by_no.get(int(no))
            if p:
                return dict(p)
            for pkt in self.packets:
                if pkt.get("no") == int(no):
                    return dict(pkt)
        return None

    def snapshot(self, last_n: int = 200) -> dict:
        with self._stats_lock:
            top_flows = sorted(
                (
                    {
                        "src": k[0],
                        "dst": k[1],
                        "protocol": k[2],
                        "dport": k[3] or None,
                        **v,
                    }
                    for k, v in self.stats.items()
                ),
                key=lambda f: f["bytes"],
                reverse=True,
            )[:20]
            recent = list(self.packets)[-last_n:]
            # light rows for backward compat
            recent_light = [
                {
                    "no": p.get("no"),
                    "time": p["time"],
                    "src": p["src"],
                    "dst": p["dst"],
                    "protocol": p["protocol"],
                    "sport": p.get("sport"),
                    "dport": p.get("dport"),
                    "length": p["length"],
                    "info": p.get("info") or "",
                }
                for p in recent
            ]
            return {
                "running": self.running,
                "error": self.error,
                "total_packets": self.packets_total,
                "buffer_size": len(self.packets),
                "bytes_total": self.bytes_total,
                "started_at": self.started_at,
                "recent_packets": recent_light,
                "top_flows": top_flows,
                "wireshark": True,
            }

    def export_csv(self) -> str:
        with self._stats_lock:
            rows = list(self.packets)
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["no", "time", "src", "dst", "protocol", "sport", "dport", "length", "info"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()

    def export_pcap_bytes(self) -> bytes:
        if not SCAPY_AVAILABLE or wrpcap is None:
            raise RuntimeError("Scapy non disponible pour export PCAP")
        with self._stats_lock:
            pkts = list(self._raw_packets)
        if not pkts:
            raise RuntimeError(
                "Aucun paquet en buffer. Démarrez une capture quelques secondes "
                "puis exportez (sudo souvent requis)."
            )
        fd, path = tempfile.mkstemp(suffix=".pcap", prefix="harmattan_")
        os.close(fd)
        try:
            wrpcap(path, pkts)
            with open(path, "rb") as f:
                data = f.read()
            if len(data) < 24:
                raise RuntimeError("Fichier PCAP généré invalide (trop court)")
            return data
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def load_pcap_file(self, path: str) -> dict:
        if not SCAPY_AVAILABLE or rdpcap is None:
            raise RuntimeError("Scapy non disponible")
        pkts = rdpcap(path)
        with self._stats_lock:
            self.packets.clear()
            self._raw_packets.clear()
            self._by_no.clear()
            self.stats.clear()
            self.packets_total = 0
            self.bytes_total = 0
            self._seq = 0
        for pkt in pkts:
            self._handle_packet(pkt)
        return self.snapshot(last_n=500)

    def clear(self) -> dict:
        """Vide le buffer (conserve l'état running)."""
        with self._stats_lock:
            self.packets.clear()
            self._raw_packets.clear()
            self._by_no.clear()
            self.stats.clear()
            self.packets_total = 0
            self.bytes_total = 0
            # keep _seq increasing for uniqueness
        return self.snapshot()

    def protocol_stats(self) -> dict:
        with self._stats_lock:
            counts: dict[str, int] = defaultdict(int)
            bytes_by: dict[str, int] = defaultdict(int)
            for p in self.packets:
                proto = p.get("protocol") or "OTHER"
                counts[proto] += 1
                bytes_by[proto] += int(p.get("length") or 0)
        items = [
            {"protocol": k, "packets": counts[k], "bytes": bytes_by[k]}
            for k in sorted(counts.keys(), key=lambda x: -counts[x])
        ]
        return {"protocols": items, "unique": len(items)}

    def follow_stream(self, no: int) -> dict:
        """Follow TCP/UDP stream à la Wireshark pour le paquet #no."""
        base = self.get_packet(no)
        if not base:
            return {"ok": False, "error": "not_found", "message": f"Paquet #{no} introuvable"}

        src, dst = base.get("src"), base.get("dst")
        sport, dport = base.get("sport"), base.get("dport")
        if not src or not dst or sport is None or dport is None:
            return {
                "ok": False,
                "error": "not_streamable",
                "message": "Pas de ports (ARP/ICMP?) — follow stream indisponible",
                "packet": base,
            }

        # endpoints unordered match
        def same_flow(p: dict) -> bool:
            a = (p.get("src"), p.get("sport"), p.get("dst"), p.get("dport"))
            b = (src, sport, dst, dport)
            rev = (dst, dport, src, sport)
            return a == b or a == rev

        with self._stats_lock:
            members = [dict(p) for p in self.packets if same_flow(p)]
            raw_by_no = {}
            # align raw packets by position in deque - better map by no via re-scan
            # We stored raw and dissected separately; match by order of no
            raw_list = list(self._raw_packets)
            disc_list = list(self.packets)
            for disc, raw in zip(disc_list, raw_list):
                if disc.get("no") is not None:
                    raw_by_no[disc["no"]] = raw

        # rebuild conversation text
        chunks = []
        client = (src, sport)  # first packet's source as client
        for p in members:
            direction = "→" if (p.get("src"), p.get("sport")) == client else "←"
            payload = b""
            raw = raw_by_no.get(p.get("no"))
            if raw is not None and SCAPY_AVAILABLE:
                try:
                    if TCP in raw and raw[TCP].payload:
                        payload = bytes(raw[TCP].payload)
                    elif UDP in raw and raw[UDP].payload:
                        payload = bytes(raw[UDP].payload)
                    elif Raw in raw:
                        payload = bytes(raw[Raw].load)
                except Exception:
                    payload = b""
            text = ""
            if payload:
                try:
                    text = payload.decode("utf-8", errors="replace")
                except Exception:
                    text = payload.hex()
            chunks.append(
                {
                    "no": p.get("no"),
                    "time": p.get("time"),
                    "direction": direction,
                    "from": f"{p.get('src')}:{p.get('sport')}",
                    "to": f"{p.get('dst')}:{p.get('dport')}",
                    "length": len(payload),
                    "text": text[:8000],
                    "hex": payload[:256].hex() if payload else "",
                    "protocol": p.get("protocol"),
                    "info": p.get("info"),
                }
            )

        # assembled client+server ascii
        assembled = []
        client_raw = b""
        server_raw = b""
        for c in chunks:
            if c["text"]:
                prefix = "C>S" if c["direction"] == "→" else "S>C"
                assembled.append(f"[{prefix} #{c['no']} {c['time']}]\n{c['text']}")
            # rebuild binary sides for HTTP reassembly
            hx = c.get("hex") or ""
            try:
                raw_part = bytes.fromhex(hx) if hx else b""
            except Exception:
                raw_part = b""
            # full payload may be truncated in hex — also keep text
            if c["direction"] == "→":
                client_raw += (c.get("text") or "").encode("utf-8", errors="ignore") if not raw_part else raw_part
            else:
                server_raw += (c.get("text") or "").encode("utf-8", errors="ignore") if not raw_part else raw_part

        http_view = _reassemble_http(client_raw, server_raw)

        return {
            "ok": True,
            "stream": {
                "client": f"{src}:{sport}",
                "server": f"{dst}:{dport}",
                "packets": len(members),
                "payload_bytes": sum(c["length"] for c in chunks),
                "http": bool(http_view.get("is_http")),
            },
            "frames": chunks,
            "assembled": "\n\n".join(assembled) if assembled else "(pas de payload applicatif — SYN/ACK seuls ?)",
            "http": http_view,
            "member_nos": [p.get("no") for p in members],
        }


def _reassemble_http(client: bytes, server: bytes) -> dict:
    """Best-effort HTTP request/response split from TCP payloads."""
    creq = client.decode("utf-8", errors="replace")
    sresp = server.decode("utf-8", errors="replace")
    is_http = creq.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")) or sresp.startswith(
        "HTTP/"
    )
    req_headers, req_body = "", ""
    resp_headers, resp_body = "", ""
    method, path, status = "", "", ""
    if is_http and creq:
        parts = creq.split("\r\n\r\n", 1)
        req_headers = parts[0]
        req_body = parts[1] if len(parts) > 1 else ""
        line0 = req_headers.split("\n", 1)[0].strip()
        bits = line0.split()
        if len(bits) >= 2:
            method, path = bits[0], bits[1]
    if is_http and sresp:
        parts = sresp.split("\r\n\r\n", 1)
        resp_headers = parts[0]
        resp_body = parts[1] if len(parts) > 1 else ""
        line0 = resp_headers.split("\n", 1)[0].strip()
        if line0.startswith("HTTP/"):
            bits = line0.split(None, 2)
            if len(bits) >= 2:
                status = bits[1]
    pretty = ""
    if is_http:
        pretty = "=== HTTP REQUEST ===\n" + (req_headers or creq[:2000])
        if req_body:
            pretty += "\n\n[body]\n" + req_body[:4000]
        pretty += "\n\n=== HTTP RESPONSE ===\n" + (resp_headers or sresp[:2000])
        if resp_body:
            pretty += "\n\n[body]\n" + resp_body[:4000]
    return {
        "is_http": is_http,
        "method": method,
        "path": path,
        "status": status,
        "request_headers": req_headers[:4000],
        "response_headers": resp_headers[:4000],
        "pretty": pretty or None,
    }

    def export_stream_text(self, no: int) -> str:
        """Export follow-stream en texte lisible (fichier)."""
        r = self.follow_stream(no)
        if not r.get("ok"):
            raise RuntimeError(r.get("message") or r.get("error") or "export failed")
        st = r["stream"]
        lines = [
            "HARMATTAN — Follow Stream Export",
            f"Generated: {datetime.now().isoformat(timespec='seconds')}",
            f"Client: {st.get('client')}",
            f"Server: {st.get('server')}",
            f"Packets: {st.get('packets')}  Payload bytes: {st.get('payload_bytes')}",
            f"Member frames: {', '.join(str(n) for n in (r.get('member_nos') or []))}",
            "=" * 60,
            "",
            r.get("assembled") or "",
            "",
            "=" * 60,
            "FRAME INDEX",
        ]
        for fr in r.get("frames") or []:
            lines.append(
                f"#{fr.get('no')} {fr.get('time')} {fr.get('direction')} "
                f"{fr.get('from')} → {fr.get('to')} len={fr.get('length')} "
                f"{fr.get('protocol')} | {fr.get('info')}"
            )
        return "\n".join(lines)

    def export_stream_json(self, no: int) -> dict:
        r = self.follow_stream(no)
        if not r.get("ok"):
            raise RuntimeError(r.get("message") or r.get("error") or "export failed")
        r = dict(r)
        r["exported_at"] = datetime.now().isoformat(timespec="seconds")
        r["format"] = "harmattan-follow-stream"
        return r

    def packet_index_for_correlation(self, limit: int = 2000) -> list[dict]:
        """Index léger pour corrélation Sahel (IP/ports)."""
        with self._stats_lock:
            rows = list(self.packets)[-limit:]
        out = []
        for p in rows:
            out.append(
                {
                    "no": p.get("no"),
                    "time": p.get("time"),
                    "src": p.get("src"),
                    "dst": p.get("dst"),
                    "sport": p.get("sport"),
                    "dport": p.get("dport"),
                    "protocol": p.get("protocol"),
                    "length": p.get("length"),
                    "info": (p.get("info") or "")[:120],
                }
            )
        return out
