"""
HARMATTAN — NetBIOS name / node status (UDP 137) + nmblookup fallback.
"""
from __future__ import annotations

import shutil
import socket
import struct
import subprocess
from typing import Optional


def _nbns_status_query(name: str = "*") -> bytes:
    """NetBIOS Node Status Request."""
    # transaction id
    tid = b"\x12\x34"
    flags = b"\x00\x00"
    qdcount = b"\x00\x01"
    rest = b"\x00\x00" * 3
    # encoded name: 32 bytes half-ASCII of 16-char name
    nm = (name.upper() + " " * 15)[:15] + "\x00"
    enc = b""
    for ch in nm.encode("ascii", "replace"):
        enc += bytes([ord("A") + (ch >> 4), ord("A") + (ch & 0x0F)])
    qname = bytes([0x20]) + enc + b"\x00"
    qtype = struct.pack("!H", 0x0021)  # NBSTAT
    qclass = struct.pack("!H", 0x0001)
    return tid + flags + qdcount + rest + qname + qtype + qclass


def _parse_nbstat(data: bytes) -> list[dict]:
    names = []
    if len(data) < 57:
        return names
    # skip header roughly; find number of names after question
    # Standard: after header+qname, answer has num names at offset
    try:
        # find 0x0021 response pattern — parse from end of question
        i = 12
        # skip qname
        while i < len(data) and data[i] != 0:
            lab = data[i]
            if lab == 0:
                break
            i += 1 + lab
        i += 1  # null
        i += 4  # type class
        if i + 12 > len(data):
            return names
        # answer name might be pointer
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1
        i += 10  # type class ttl
        if i + 2 > len(data):
            return names
        rdlen = struct.unpack("!H", data[i : i + 2])[0]
        i += 2
        if i >= len(data):
            return names
        num = data[i]
        i += 1
        for _ in range(min(num, 32)):
            if i + 18 > len(data):
                break
            raw = data[i : i + 15]
            suffix = data[i + 15]
            flags = struct.unpack("!H", data[i + 16 : i + 18])[0]
            i += 18
            try:
                n = raw.decode("ascii", "ignore").strip()
            except Exception:
                n = raw.hex()
            if n:
                names.append(
                    {
                        "name": n,
                        "suffix": suffix,
                        "group": bool(flags & 0x8000),
                        "type": _suffix_type(suffix),
                    }
                )
    except Exception:
        pass
    return names


def _suffix_type(s: int) -> str:
    return {
        0x00: "workstation",
        0x03: "messenger",
        0x20: "file_server",
        0x1B: "domain_master",
        0x1C: "domain_controller",
        0x1D: "master_browser",
        0x1E: "browser_election",
    }.get(s, f"0x{s:02x}")


def query_udp(ip: str, timeout: float = 1.5) -> dict:
    out = {"ip": ip, "ok": False, "names": [], "via": "udp137"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_nbns_status_query("*"), (ip, 137))
        data, _ = sock.recvfrom(4096)
        sock.close()
        names = _parse_nbstat(data)
        out["names"] = names
        out["ok"] = bool(names)
        if names:
            # prefer unique workstation name
            for n in names:
                if not n.get("group") and n.get("type") == "workstation":
                    out["hostname"] = n["name"]
                    break
            if "hostname" not in out:
                out["hostname"] = names[0]["name"]
    except Exception as e:
        out["error"] = str(e)
    return out


def query_nmblookup(ip: str) -> dict:
    out = {"ip": ip, "ok": False, "names": [], "via": "nmblookup"}
    if not shutil.which("nmblookup"):
        return out
    try:
        p = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        names = []
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("Looking") or line.startswith("No"):
                continue
            # NAME <00> - UNIQUE
            m = line.split()
            if len(m) >= 2 and m[0] and not m[0].startswith("MAC"):
                names.append({"name": m[0], "raw": line})
        if names:
            out["ok"] = True
            out["names"] = names
            out["hostname"] = names[0]["name"]
    except Exception as e:
        out["error"] = str(e)
    return out


def probe(ip: str, timeout: float = 1.5) -> dict:
    r = query_udp(ip, timeout=timeout)
    if r.get("ok"):
        return r
    r2 = query_nmblookup(ip)
    if r2.get("ok"):
        return r2
    return r if r.get("error") else r2


def probe_many(hosts: list[str], max_hosts: int = 50) -> dict:
    results = []
    for ip in hosts[:max_hosts]:
        r = probe(ip)
        if r.get("ok"):
            results.append(r)
    return {"probed": min(len(hosts), max_hosts), "found": len(results), "hosts": results}
