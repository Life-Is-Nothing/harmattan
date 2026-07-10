"""
HARMATTAN — SNMP v2c probe (UDP, no external deps).
GET sysDescr / sysName / sysObjectID; optional snmpwalk if present.
"""
from __future__ import annotations

import re
import shutil
import socket
import struct
import subprocess
from typing import Optional

from core.config import SNMP_COMMUNITIES
from core.logging_setup import get_logger

log = get_logger("harmattan.snmp")

# OIDs
OID_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYSOBJECTID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
OID_SYSNAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
OID_SYSLOCATION = (1, 3, 6, 1, 2, 1, 1, 6, 0)


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID too short")
    first = 40 * oid[0] + oid[1]
    out = bytes([first])
    for n in oid[2:]:
        if n < 0:
            raise ValueError("negative OID")
        stack = [n & 0x7F]
        n >>= 7
        while n:
            stack.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(stack))
    return out


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = []
    x = n
    while x:
        b.append(x & 0xFF)
        x >>= 8
    b.reverse()
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _encode_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    neg = n < 0
    if neg:
        n = -n
    b = []
    while n:
        b.append(n & 0xFF)
        n >>= 8
    b.reverse()
    if not neg and b[0] & 0x80:
        b = [0] + b
    if neg:
        # two's complement simplified not needed for SNMP request ids
        pass
    return _tlv(0x02, bytes(b))


def _encode_octet(s: bytes) -> bytes:
    return _tlv(0x04, s)


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_oid_tlv(oid: tuple[int, ...]) -> bytes:
    return _tlv(0x06, _encode_oid(oid))


def build_snmp_get(community: str, oid: tuple[int, ...], req_id: int = 1) -> bytes:
    """SNMPv2c GetRequest PDU."""
    varbind = _tlv(0x30, _encode_oid_tlv(oid) + _encode_null())
    varbind_list = _tlv(0x30, varbind)
    # GetRequest-PDU tag 0xA0
    pdu = _tlv(
        0xA0,
        _encode_int(req_id)
        + _encode_int(0)  # error-status
        + _encode_int(0)  # error-index
        + varbind_list,
    )
    version = _encode_int(1)  # SNMPv2c
    comm = _encode_octet(community.encode("utf-8", errors="ignore"))
    return _tlv(0x30, version + comm + pdu)


def _parse_strings(data: bytes) -> list[str]:
    """Best-effort extract printable OCTET STRINGs from BER response."""
    out = []
    i = 0
    while i < len(data) - 2:
        if data[i] == 0x04:
            ln = data[i + 1]
            if ln < 0x80 and i + 2 + ln <= len(data):
                raw = data[i + 2 : i + 2 + ln]
                try:
                    s = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    s = ""
                if s and re.search(r"[A-Za-z0-9]", s):
                    out.append(s)
                i += 2 + ln
                continue
        i += 1
    return out


def snmp_get(
    host: str,
    oid: tuple[int, ...] = OID_SYSDESCR,
    community: str = "public",
    timeout: float = 1.5,
    port: int = 161,
) -> Optional[str]:
    try:
        pkt = build_snmp_get(community, oid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        strings = _parse_strings(data)
        return strings[0] if strings else (data.hex()[:80] if data else None)
    except Exception as e:
        log.debug("snmp_get %s: %s", host, e)
        return None


def probe_host(
    host: str,
    communities: list[str] | None = None,
    timeout: float = 1.2,
) -> dict:
    """Try communities; return sysDescr/sysName if any respond."""
    communities = communities or list(SNMP_COMMUNITIES) or ["public"]
    result = {
        "ip": host,
        "ok": False,
        "community": None,
        "sysDescr": None,
        "sysName": None,
        "sysObjectID": None,
        "sysLocation": None,
        "via": None,
    }
    # Prefer net-snmp CLI if available (more complete)
    if shutil.which("snmpget"):
        for comm in communities:
            try:
                cmd = [
                    "snmpget",
                    "-v2c",
                    "-c",
                    comm,
                    "-t",
                    str(max(1, int(timeout))),
                    "-r",
                    "0",
                    "-OQv",
                    host,
                    "sysDescr.0",
                ]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
                if p.returncode == 0 and p.stdout.strip():
                    result["ok"] = True
                    result["community"] = comm
                    result["sysDescr"] = p.stdout.strip().strip('"')
                    result["via"] = "snmpget"
                    for oid_name, key in (
                        ("sysName.0", "sysName"),
                        ("sysObjectID.0", "sysObjectID"),
                        ("sysLocation.0", "sysLocation"),
                    ):
                        p2 = subprocess.run(
                            [
                                "snmpget",
                                "-v2c",
                                "-c",
                                comm,
                                "-t",
                                "1",
                                "-r",
                                "0",
                                "-OQv",
                                host,
                                oid_name,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=3,
                        )
                        if p2.returncode == 0 and p2.stdout.strip():
                            result[key] = p2.stdout.strip().strip('"')
                    return result
            except Exception:
                continue

    for comm in communities:
        descr = snmp_get(host, OID_SYSDESCR, comm, timeout=timeout)
        if descr:
            result["ok"] = True
            result["community"] = comm
            result["sysDescr"] = descr
            result["via"] = "udp"
            result["sysName"] = snmp_get(host, OID_SYSNAME, comm, timeout=timeout)
            result["sysObjectID"] = snmp_get(host, OID_SYSOBJECTID, comm, timeout=timeout)
            result["sysLocation"] = snmp_get(host, OID_SYSLOCATION, comm, timeout=timeout)
            return result
    return result


def probe_many(hosts: list[str], max_hosts: int = 40, timeout: float = 1.0) -> dict:
    results = []
    for ip in hosts[:max_hosts]:
        r = probe_host(ip, timeout=timeout)
        if r.get("ok"):
            results.append(r)
    return {
        "probed": min(len(hosts), max_hosts),
        "responding": len(results),
        "hosts": results,
    }
