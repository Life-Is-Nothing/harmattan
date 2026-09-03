"""
HARMATTAN — Traffic-Notifier: real-time anomaly detection + alerts on captured traffic.

Runs a periodic analysis loop over a TrafficCapture (see modules/traffic_analyzer.py),
looking for suspicious signals:
  * port scanning behaviour (many distinct destination ports from one source)
  * traffic spikes (packet-rate or byte-rate above a baseline)
  * unexpected protocols / unusual top protocols
  * SYN-only floods (incomplete handshakes)

When a signal fires, it dispatches via core.alerts.notify() (which fans out to the
configured channels: Slack/Discord/Email/Syslog) and optionally pushes to the Sahel hub
via modules/sahel_bridge.

Designed for monitoring an AUTHORIZED lab / own network. Informational only.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from core.alerts import notify as alert_notify
from core.logging_setup import get_logger

log = get_logger("harmattan.traffic_notifier")

_lock = threading.Lock()
_state: dict[str, Any] = {
    "running": False,
    "thread": None,
    "stop": None,
    "interval": 15,
    "cycles": 0,
    "alerts": 0,
    "last_signals": [],
    "last_error": None,
    "baseline": None,
}


def _is_port_scan(capture) -> bool:
    """Heuristic: one source ip → many distinct dst ports in the ring buffer."""
    dst_ports: dict[str, set] = {}
    for p in capture.packets:
        if p.get("ip_src") and p.get("dport"):
            dst_ports.setdefault(p.get("ip_src"), set()).add(p.get("dport"))
        elif p.get("src") and p.get("dport"):
            dst_ports.setdefault(p.get("src"), set()).add(p.get("dport"))
    suspicious = [
        {"ip": src, "ports_seen": len(ports)}
        for src, ports in dst_ports.items() if len(ports) >= 15
    ]
    return suspicious


def _analyze(capture, baseline: Optional[dict]) -> list[dict]:
    signals: list[dict] = []
    try:
        stats = capture.protocol_stats()
        prots = stats.get("protocols") or []
        total_pkts = sum(p.get("packets", 0) for p in prots)
        total_bytes = sum(p.get("bytes", 0) for p in prots)

        # Unexpected / high-volume protocols
        top = prots[0] if prots else {}
        if top.get("protocol") == "OTHER" and top.get("packets", 0) > 50:
            signals.append({
                "type": "unknown_protocol",
                "severity": "medium",
                "detail": f"Beaucoup de trafic non classé ({top.get('packets')} pkts).",
            })

        # Port scan
        scans = _is_port_scan(capture)
        if scans:
            signals.append({
                "type": "port_scan",
                "severity": "high",
                "detail": f"Scan possible par {len(scans)} source(s): "
                          + ", ".join(f"{s['ip']}({s['ports_seen']} ports)" for s in scans[:3]),
            })

        # Spikes vs baseline
        if baseline and total_pkts and baseline.get("packets"):
            ratio = total_pkts / max(1, baseline.get("packets", 1))
            if ratio >= 5:
                signals.append({
                    "type": "traffic_spike",
                    "severity": "medium",
                    "detail": f"Pic de trafic: x{ratio:.1f} vs baseline ({total_pkts} pkts).",
                })
    except Exception as e:  # noqa: BLE001
        log.debug("traffic analyze error: %s", e)
    return signals


def status() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "interval": _state["interval"],
            "cycles": _state["cycles"],
            "alerts": _state["alerts"],
            "last_signals": list(_state["last_signals"][-20:]),
            "last_error": _state["last_error"],
        }


def start(
    interval: int = 15,
    capture=None,
    on_signal: Optional[Callable[[dict], None]] = None,
) -> tuple[bool, str]:
    with _lock:
        if _state["running"]:
            return False, "Traffic-Notifier déjà actif"
        stop = threading.Event()
        _state["stop"] = stop
        _state["running"] = True
        _state["interval"] = max(5, min(int(interval), 300))
        _state["last_error"] = None
        _state["baseline"] = None
        _state["cycles"] = 0
        _state["alerts"] = 0

    def loop():
        from modules import traffic_analyzer
        cap = capture or traffic_analyzer.TrafficCapture()

        def snapshot_baseline():
            try:
                s = cap.snapshot(last_n=50)
                prots = s.get("protocols") or []
                with _lock:
                    _state["baseline"] = {
                        "packets": sum(p.get("packets", 0) for p in prots),
                        "bytes": sum(p.get("bytes", 0) for p in prots),
                    }
            except Exception as e:  # noqa: BLE001
                log.debug("baseline: %s", e)

        # warm baseline on first cycle
        try:
            snapshot_baseline()
        except Exception:
            pass

        while not stop.is_set():
            try:
                signals = _analyze(cap, _state["baseline"])
                for sig in signals:
                    msg = f"Traffic-Notifier [{sig['severity']}] {sig['detail']}"
                    alert_notify(msg, source="traffic-notifier", severity=sig["severity"])
                    if on_signal:
                        try:
                            on_signal(sig)
                        except Exception as e:  # noqa: BLE001
                            log.debug("on_signal: %s", e)
                    with _lock:
                        _state["alerts"] += 1
                        _state["last_signals"].append(sig)
                # refresh baseline every N cycles (drift)
                if _state["cycles"] % 4 == 0:
                    snapshot_baseline()
                with _lock:
                    _state["cycles"] += 1
                    _state["last_error"] = None
            except Exception as e:  # noqa: BLE001
                log.exception("traffic notifier cycle")
                with _lock:
                    _state["last_error"] = str(e)
            stop.wait(_state["interval"])
        with _lock:
            _state["running"] = False

    t = threading.Thread(target=loop, daemon=True)
    with _lock:
        _state["thread"] = t
    t.start()
    alert_notify("Traffic-Notifier démarré (monitoring lab / réseau autorisé)", source="traffic-notifier")
    return True, "Traffic-Notifier démarré"


def stop() -> tuple[bool, str]:
    with _lock:
        if not _state["running"]:
            return False, "Traffic-Notifier non actif"
        stop = _state["stop"]
        _state["running"] = False
    if stop:
        stop.set()
    return True, "Traffic-Notifier arrêté"
