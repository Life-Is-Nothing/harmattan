"""
HARMATTAN — Thread-safe live packet capture with bounded buffer.
"""
from __future__ import annotations

import csv
import io
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

from core.config import TRAFFIC_BUFFER
from core.logging_setup import get_logger

log = get_logger("harmattan.traffic")

try:
    from scapy.all import IP, TCP, UDP, sniff, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    wrpcap = None  # type: ignore


class TrafficCapture:
    """Capture de paquets thread-safe, buffer borné (deque)."""

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = ""):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.packets: deque = deque(maxlen=TRAFFIC_BUFFER)
        self._raw_packets: deque = deque(maxlen=min(TRAFFIC_BUFFER, 2000))
        self.stats: dict = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self._stats_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.error: Optional[str] = None
        self.started_at: Optional[str] = None
        self.bytes_total = 0
        self.packets_total = 0

    def _handle_packet(self, pkt) -> None:
        if IP not in pkt:
            return
        proto = "OTHER"
        sport = dport = None
        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)

        src, dst = pkt[IP].src, pkt[IP].dst
        length = len(pkt)
        entry = {
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": src,
            "dst": dst,
            "protocol": proto,
            "sport": sport,
            "dport": dport,
            "length": length,
        }
        with self._stats_lock:
            self.packets.append(entry)
            self._raw_packets.append(pkt)
            self.packets_total += 1
            self.bytes_total += length
            key = (src, dst, proto, dport or 0)
            self.stats[key]["packets"] += 1
            self.stats[key]["bytes"] += length
            # Cap unique flow keys
            if len(self.stats) > 2000:
                # drop lowest traffic keys
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

    def snapshot(self, last_n: int = 100) -> dict:
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
            return {
                "running": self.running,
                "error": self.error,
                "total_packets": self.packets_total,
                "buffer_size": len(self.packets),
                "bytes_total": self.bytes_total,
                "started_at": self.started_at,
                "recent_packets": recent,
                "top_flows": top_flows,
            }

    def export_csv(self) -> str:
        with self._stats_lock:
            rows = list(self.packets)
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["time", "src", "dst", "protocol", "sport", "dport", "length"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()

    def export_pcap_bytes(self) -> bytes:
        """Export raw captured packets as PCAP."""
        if not SCAPY_AVAILABLE or wrpcap is None:
            raise RuntimeError("Scapy non disponible pour export PCAP")
        with self._stats_lock:
            pkts = list(self._raw_packets)
        if not pkts:
            raise RuntimeError("Aucun paquet brut en buffer (relancez une capture)")
        buf = io.BytesIO()
        wrpcap(buf, pkts)
        return buf.getvalue()
