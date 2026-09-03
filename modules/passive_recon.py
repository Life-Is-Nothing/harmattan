"""
HARMATTAN — Passive LAN recon (mDNS / SSDP / DHCP / NetBIOS listen).
No active port scan; best-effort observation only.
"""
from __future__ import annotations

import socket
import struct
import threading
from datetime import datetime
from typing import Any, Callable, Optional


def passive_discover(
    timeout: float = 4.0,
    iface: str | None = None,
    progress: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    """
    Run lightweight passive/semi-passive probes:
    - mDNS multicast listen + query
    - SSDP M-SEARCH
    - NetBIOS name service probe (broadcast)
    - DHCP informal listen (best-effort, may need CAP_NET_RAW)
    """
    started = datetime.now().isoformat(timespec="seconds")
    hosts: dict[str, dict] = {}
    events: list[dict] = []

    def _note(ip: str, source: str, **extra):
        if not ip:
            return
        h = hosts.setdefault(ip, {"ip": ip, "sources": [], "hints": []})
        if source not in h["sources"]:
            h["sources"].append(source)
        for k, v in extra.items():
            if v and k not in ("ip",):
                if k == "hostname" and v:
                    h["hostname"] = v
                elif k == "vendor" and v:
                    h["vendor"] = v
                else:
                    h["hints"].append(f"{k}={v}")
        events.append({"ip": ip, "source": source, **extra})

    if progress:
        progress(5, "mDNS…")
    try:
        from modules.mdns_discovery import discover_mdns_ssdp

        pack = discover_mdns_ssdp(timeout=min(timeout, 3.0))
        for r in pack.get("mdns") or []:
            if r.get("ip") and not r.get("error"):
                _note(r["ip"], "mdns")
        for r in pack.get("ssdp") or []:
            if r.get("ip") and not r.get("error"):
                _note(
                    r["ip"],
                    "ssdp",
                    hostname=r.get("server") or r.get("usn") or "",
                    vendor=r.get("server") or "",
                )
    except Exception as e:
        events.append({"source": "mdns", "error": str(e)[:120]})

    if progress:
        progress(40, "NetBIOS…")
    for ip, name in _netbios_broadcast(timeout=min(2.0, timeout)):
        _note(ip, "netbios", hostname=name)

    if progress:
        progress(70, "DHCP listen…")
    dhcp_hits = _dhcp_listen(timeout=min(2.0, timeout))
    for hit in dhcp_hits:
        _note(hit.get("ip") or "", "dhcp", hostname=hit.get("hostname") or "", mac=hit.get("mac") or "")

    if progress:
        progress(100, "OK")

    host_list = sorted(hosts.values(), key=lambda h: h.get("ip") or "")
    return {
        "ok": True,
        "started": started,
        "finished": datetime.now().isoformat(timespec="seconds"),
        "timeout": timeout,
        "hosts": host_list,
        "count": len(host_list),
        "events": events[:200],
        "sources": sorted({s for h in host_list for s in h.get("sources") or []}),
    }


def _netbios_broadcast(timeout: float = 2.0) -> list[tuple[str, str]]:
    """Send NetBIOS name query * (broadcast) and collect replies."""
    results: list[tuple[str, str]] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        # NBNS query for '*'
        txn = b"\x12\x34"
        flags = b"\x01\x10"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        # encoded name for *
        name = b" CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        qtype = b"\x00\x21\x00\x01"  # NBSTAT
        pkt = txn + flags + counts + name + qtype
        sock.sendto(pkt, ("255.255.255.255", 137))
        end = datetime.now().timestamp() + timeout
        seen = set()
        while datetime.now().timestamp() < end:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                name_str = ""
                if len(data) > 57:
                    # crude: look for printable hostname after header
                    chunk = data[57:57 + 15]
                    name_str = "".join(chr(b) if 32 <= b < 127 else "" for b in chunk).strip()
                results.append((ip, name_str))
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass
    return results


def _dhcp_listen(timeout: float = 2.0) -> list[dict]:
    """Best-effort UDP 67/68 listen for DHCP traffic (may fail without privileges)."""
    hits: list[dict] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", 68))
        except OSError:
            # cannot bind privileged port — skip
            sock.close()
            return hits
        sock.settimeout(timeout)
        end = datetime.now().timestamp() + timeout
        while datetime.now().timestamp() < end:
            try:
                data, addr = sock.recvfrom(2048)
                if len(data) < 240:
                    continue
                # BOOTP yiaddr at offset 16
                yiaddr = socket.inet_ntoa(data[16:20])
                chaddr = ":".join(f"{b:02x}" for b in data[28:34])
                hostname = ""
                # options after magic cookie 236+4
                opts = data[240:]
                i = 0
                while i < len(opts):
                    code = opts[i]
                    if code in (0xFF, 255):
                        break
                    if code == 0:
                        i += 1
                        continue
                    if i + 1 >= len(opts):
                        break
                    ln = opts[i + 1]
                    val = opts[i + 2 : i + 2 + ln]
                    if code == 12:  # hostname
                        try:
                            hostname = val.decode("utf-8", errors="ignore")
                        except Exception:
                            hostname = ""
                    i += 2 + ln
                hits.append({"ip": yiaddr if yiaddr != "0.0.0.0" else addr[0], "mac": chaddr, "hostname": hostname})
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass
    return hits


# Background passive monitor (optional long-running)
_passive_thread: Optional[threading.Thread] = None
_passive_stop = threading.Event()
_passive_buffer: list[dict] = []
_passive_lock = threading.Lock()


def start_passive_monitor(interval: float = 30.0) -> dict:
    global _passive_thread
    if _passive_thread and _passive_thread.is_alive():
        return {"ok": True, "running": True, "message": "already_running"}
    _passive_stop.clear()

    def _loop():
        while not _passive_stop.is_set():
            try:
                pack = passive_discover(timeout=3.0)
                with _passive_lock:
                    _passive_buffer.append({
                        "ts": datetime.now().isoformat(timespec="seconds"),
                        "count": pack.get("count"),
                        "hosts": pack.get("hosts"),
                    })
                    del _passive_buffer[:-20]
            except Exception:
                pass
            _passive_stop.wait(interval)

    _passive_thread = threading.Thread(target=_loop, daemon=True, name="passive-monitor")
    _passive_thread.start()
    return {"ok": True, "running": True}


def stop_passive_monitor() -> dict:
    _passive_stop.set()
    return {"ok": True, "running": False}


def passive_monitor_status() -> dict:
    alive = bool(_passive_thread and _passive_thread.is_alive())
    with _passive_lock:
        last = _passive_buffer[-1] if _passive_buffer else None
        n = len(_passive_buffer)
    return {"ok": True, "running": alive, "snapshots": n, "last": last}
