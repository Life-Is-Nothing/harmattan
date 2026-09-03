"""
HARMATTAN — NetFlow-Export: emit captured traffic as NetFlow/IPFIX-style records.

Provides a best-effort serializer from captured packet dicts (modules/traffic_analyzer)
into NetFlow v9-style template records, and a tiny UDP collector that can stream them to
an external collector/SIEM (e.g. a local nfcapd or NetFlow listener) on an authorized
lab network.

Pure Python, no external dependency. Informational / lab use only.
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.netflow_export")

# NetFlow v9 field type codes (subset we can map).
FIELD_SRCADDR = 8
FIELD_DSTADDR = 12
FIELD_SRCPORT = 7
FIELD_DSTPORT = 11
FIELD_PROTO = 4
FIELD_PKTS = 2
FIELD_BYTES = 1
FIELD_L4SRCPORT = 7
FIELD_L4DSTPORT = 11

FLOW_RECORD_LEN = 48  # bytes per record (fixed simplified format)


class NetFlowExporter:
    """Simple NetFlow v9-style exporter that streams records over UDP."""

    def __init__(self, collector_host: str = "127.0.0.1", collector_port: int = 9996,
                 source_id: int = 1, enabled: bool = True):
        self.collector = (collector_host, collector_port)
        self.source_id = source_id & 0xFFFFFFFF
        self.enabled = enabled
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.exported = 0
        if enabled:
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except OSError as e:
                log.warning("NetFlow socket init failed: %s", e)
                self._sock = None

    def _inet_aton(self, ip: str) -> bytes:
        try:
            return socket.inet_aton(ip)
        except OSError:
            return b"\x00\x00\x00\x00"

    def to_netflow_record(self, pkt: dict) -> Optional[bytes]:
        """Serialize one packet dict into a fixed NetFlow v9 data record."""
        src = pkt.get("ip_src") or pkt.get("src") or "0.0.0.0"
        dst = pkt.get("ip_dst") or pkt.get("dst") or "0.0.0.0"
        sport = int(pkt.get("sport") or pkt.get("srcport") or 0)
        dport = int(pkt.get("dport") or pkt.get("dstport") or 0)
        proto_map = {
            "tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58,
        }
        proto = proto_map.get((pkt.get("protocol") or "").lower(), 0)
        pkts = int(pkt.get("packets") or 1)
        length = int(pkt.get("length") or 0)
        try:
            return struct.pack(
                "!4s4sHHHII",
                self._inet_aton(src),
                self._inet_aton(dst),
                sport, dport, proto, pkts, length,
            )
        except (struct.error, TypeError, ValueError):
            return None

    def send(self, record: bytes) -> None:
        if not self.enabled or not self._sock or not record:
            return
        try:
            with self._lock:
                self._sock.sendto(record, self.collector)
                self.exported += 1
        except OSError as e:
            log.debug("netflow send: %s", e)

    def send_packets(self, packets: list[dict], chunk: int = 20) -> dict:
        """Send a batch of packet dicts. Returns stats."""
        sent = 0
        for pkt in packets or []:
            rec = self.to_netflow_record(pkt)
            if rec:
                self.send(rec)
                sent += 1
        return {"sent": sent, "exported_total": self.exported}

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def export_packets(packets: list[dict], collector_host: str = "127.0.0.1",
                   collector_port: int = 9996, source_id: int = 1) -> dict:
    """One-shot helper: build exporter, send records, return stats."""
    ex = NetFlowExporter(collector_host, collector_port, source_id, enabled=True)
    try:
        return ex.send_packets(packets)
    finally:
        ex.close()


def summarize(result: dict) -> str:
    return f"NetFlow-Export: {result.get('sent', 0)} enregistrement(s) envoyé(s)"
