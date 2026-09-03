"""
HARMATTAN — Honeypot-Lite: low-interaction decoy listeners that log connections.

Opens a set of TCP listeners (default 21, 22, 8080) on loopback / a chosen bind
address. Any inbound connection is recorded (source IP, port, banner sent, timestamp)
and can be surfaced as an alert via core.alerts.notify(). Purely passive and
pedagogical — it never interacts with real external systems beyond accepting a TCP
handshake from the LAB / local host.

This is intended for training labs and authorized testing of one's own network only.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Any

from core.alerts import notify as alert_notify
from core.logging_setup import get_logger

log = get_logger("harmattan.honeypot_lite")

DEFAULT_PORTS = [21, 22, 8080]
# Fake service banners to make the decoy look plausible (no real service behind it).
_BANNERS = {
    21: b"220 (vsFTPd 3.0.3)\r\n",
    22: b"SSH-2.0-OpenSSH_8.9p1\r\n",
    23: b"Telnet (Cisco IOS)\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
    443: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
}

_lock = threading.Lock()
_state: dict[str, Any] = {
    "running": False,
    "sockets": [],
    "threads": [],
    "stop": None,
    "bind": "0.0.0.0",
    "ports": list(DEFAULT_PORTS),
    "connections": 0,
    "last_connections": [],
    "last_error": None,
}


def status() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "bind": _state["bind"],
            "ports": list(_state["ports"]),
            "connections": _state["connections"],
            "last_connections": list(_state["last_connections"][-20:]),
            "last_error": _state["last_error"],
        }


def _handle(conn: socket.socket, addr, port: int) -> None:
    ip = addr[0]
    banner = _BANNERS.get(port, b"Welcome\r\n")
    try:
        conn.settimeout(3)
        # Send a banner, then read a little (optional), then close.
        try:
            conn.sendall(banner)
        except OSError:
            pass
        try:
            conn.recv(256)
        except socket.timeout:
            pass
        except OSError:
            pass
    except Exception as e:  # noqa: BLE001
        log.debug("honeypot handle error: %s", e)
    finally:
        try:
            conn.close()
        except OSError:
            pass
        with _lock:
            _state["connections"] += 1
            _state["last_connections"].append(
                {"ip": ip, "port": port, "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
            )
    log.info("Honeypot connection from %s on port %s", ip, port)


def _serve(port: int, bind: str, stop: threading.Event):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind, port))
        srv.listen(5)
        srv.settimeout(0.5)
    except OSError as e:
        log.error("Honeypot cannot bind %s:%s: %s", bind, port, e)
        with _lock:
            _state["last_error"] = f"bind {port}: {e}"
        return
    with _lock:
        _state["sockets"].append(srv)
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn, addr, port), daemon=True).start()
    try:
        srv.close()
    except OSError:
        pass


def start(bind: str = "0.0.0.0", ports: list[int] | None = None) -> tuple[bool, str]:
    with _lock:
        if _state["running"]:
            return False, "Honeypot déjà actif"
        stop = threading.Event()
        _state["stop"] = stop
        _state["bind"] = bind or "0.0.0.0"
        _state["ports"] = [int(p) for p in (ports or DEFAULT_PORTS)]
        _state["sockets"] = []
        _state["threads"] = []
        _state["connections"] = 0
        _state["last_connections"] = []
        _state["last_error"] = None
        _state["running"] = True

    for p in _state["ports"]:
        t = threading.Thread(target=_serve, args=(p, _state["bind"], stop), daemon=True)
        t.start()
        _state["threads"].append(t)
    ports = ", ".join(str(p) for p in _state["ports"])
    alert_notify(f"Honeypot-Lite démarré sur ports {ports} (lab / test uniquement)", source="honeypot-lite")
    return True, f"Honeypot-Lite démarré sur ports {ports}"


def stop() -> tuple[bool, str]:
    with _lock:
        if not _state["running"]:
            return False, "Honeypot non actif"
        stop = _state["stop"]
        _state["running"] = False
    if stop:
        stop.set()
    with _lock:
        _state["sockets"] = []
        _state["threads"] = []
    return True, "Honeypot-Lite arrêté"
