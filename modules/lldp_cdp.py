"""
HARMATTAN — LLDP / CDP neighbor discovery (Scapy, CAP_NET_RAW / root).
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.lldp")

try:
    from scapy.all import Ether, SNAP, sniff, conf

    SCAPY = True
except Exception:
    SCAPY = False

_HAS_LLDP = False
_HAS_CDP = False
if SCAPY:
    try:
        from scapy.contrib.lldp import (
            LLDPDU,
            LLDPDUChassisID,
            LLDPDUPortID,
            LLDPDUSystemName,
        )

        _HAS_LLDP = True
    except Exception:
        log.debug("scapy.contrib.lldp unavailable")
    try:
        from scapy.contrib.cdp import (
            CDPv2_HDR,
            CDPMsgDeviceID,
            CDPMsgPortID,
            CDPMsgPlatform,
            CDPMsgSoftwareVersion,
        )

        _HAS_CDP = True
    except Exception:
        log.debug("scapy.contrib.cdp unavailable")


def _printable(raw: bytes, limit: int = 64) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw)
    parts = [x.strip() for x in text.split() if len(x.strip()) > 2]
    return (parts[0] if parts else text.strip())[:limit]


def _parse_lldp(pkt) -> Optional[dict]:
    if not _HAS_LLDP:
        # ethertype 0x88cc
        try:
            if pkt.haslayer(Ether) and pkt[Ether].type == 0x88CC:
                raw = bytes(pkt.payload)
                return {
                    "proto": "LLDP",
                    "src_mac": pkt[Ether].src,
                    "system_name": _printable(raw),
                    "chassis": None,
                    "port": None,
                }
        except Exception:
            return None
        return None
    try:
        if not pkt.haslayer(LLDPDU) and not (
            pkt.haslayer(Ether) and pkt[Ether].type == 0x88CC
        ):
            return None
        d = {
            "proto": "LLDP",
            "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
            "chassis": None,
            "port": None,
            "system_name": None,
        }
        try:
            if pkt.haslayer(LLDPDUChassisID):
                cid = getattr(pkt[LLDPDUChassisID], "id", None)
                d["chassis"] = (
                    cid.decode("utf-8", "ignore")
                    if isinstance(cid, (bytes, bytearray))
                    else str(cid)
                )
        except Exception:
            pass
        try:
            if pkt.haslayer(LLDPDUPortID):
                pid = getattr(pkt[LLDPDUPortID], "id", None)
                d["port"] = (
                    pid.decode("utf-8", "ignore")
                    if isinstance(pid, (bytes, bytearray))
                    else str(pid)
                )
        except Exception:
            pass
        try:
            if pkt.haslayer(LLDPDUSystemName):
                sn = pkt[LLDPDUSystemName].system_name
                d["system_name"] = (
                    sn.decode("utf-8", "ignore")
                    if isinstance(sn, (bytes, bytearray))
                    else str(sn)
                )
        except Exception:
            pass
        if not d["system_name"]:
            try:
                d["system_name"] = _printable(bytes(pkt))
            except Exception:
                pass
        return d if (d["chassis"] or d["system_name"] or d["src_mac"]) else None
    except Exception as e:
        log.debug("parse lldp: %s", e)
        return None


def _parse_cdp(pkt) -> Optional[dict]:
    try:
        is_cdp = False
        if _HAS_CDP and pkt.haslayer(CDPv2_HDR):
            is_cdp = True
        elif pkt.haslayer(Ether):
            dst = (pkt[Ether].dst or "").lower()
            if dst == "01:00:0c:cc:cc:cc":
                is_cdp = True
        if not is_cdp:
            return None
        d = {
            "proto": "CDP",
            "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
            "device_id": None,
            "port": None,
            "platform": None,
            "software": None,
        }
        if _HAS_CDP:
            if pkt.haslayer(CDPMsgDeviceID):
                val = pkt[CDPMsgDeviceID].val
                d["device_id"] = (
                    val.decode("utf-8", "ignore")
                    if isinstance(val, (bytes, bytearray))
                    else str(val)
                )
            if pkt.haslayer(CDPMsgPortID):
                val = pkt[CDPMsgPortID].iface
                d["port"] = (
                    val.decode("utf-8", "ignore")
                    if isinstance(val, (bytes, bytearray))
                    else str(val)
                )
            if pkt.haslayer(CDPMsgPlatform):
                val = pkt[CDPMsgPlatform].val
                d["platform"] = (
                    val.decode("utf-8", "ignore")
                    if isinstance(val, (bytes, bytearray))
                    else str(val)
                )
            if pkt.haslayer(CDPMsgSoftwareVersion):
                val = pkt[CDPMsgSoftwareVersion].val
                d["software"] = (
                    val.decode("utf-8", "ignore")
                    if isinstance(val, (bytes, bytearray))
                    else str(val)
                )
        if not d["device_id"]:
            d["device_id"] = _printable(bytes(pkt.payload) if pkt.payload else bytes(pkt))
        if d["device_id"] or d["platform"] or d["src_mac"]:
            return d
    except Exception as e:
        log.debug("parse cdp: %s", e)
    return None


def discover(
    iface: str | None = None,
    timeout: float = 8.0,
    progress: Optional[Callable] = None,
) -> dict:
    started = datetime.now().isoformat(timespec="seconds")
    if not SCAPY:
        return {
            "started": started,
            "ok": False,
            "error": "scapy_missing",
            "neighbors": [],
            "count": 0,
        }

    neighbors = []
    seen = set()

    def _on(pkt):
        for parser in (_parse_lldp, _parse_cdp):
            try:
                n = parser(pkt)
            except Exception:
                n = None
            if not n:
                continue
            key = (
                n.get("proto"),
                n.get("src_mac"),
                n.get("system_name") or n.get("device_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            neighbors.append(n)

    if progress:
        progress(10, f"Écoute LLDP/CDP {timeout:.0f}s…")

    bpf = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or ether dst 01:80:c2:00:00:0e"
    try:
        conf.verb = 0
        sniff(
            iface=iface or conf.iface,
            filter=bpf,
            prn=_on,
            timeout=timeout,
            store=False,
        )
    except PermissionError:
        return {
            "started": started,
            "ok": False,
            "error": "permission",
            "message": "CAP_NET_RAW / root requis pour LLDP/CDP",
            "neighbors": [],
            "count": 0,
        }
    except Exception as e:
        log.exception("lldp sniff")
        return {
            "started": started,
            "ok": False,
            "error": str(e),
            "neighbors": neighbors,
            "count": len(neighbors),
        }

    if progress:
        progress(100, f"{len(neighbors)} voisin(s)")

    return {
        "started": started,
        "ok": True,
        "iface": iface or str(conf.iface),
        "timeout": timeout,
        "neighbors": neighbors,
        "count": len(neighbors),
        "finished": datetime.now().isoformat(timespec="seconds"),
    }
