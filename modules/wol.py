"""Wake-on-LAN magic packet sender."""
from __future__ import annotations

import re
import socket


def send_wol(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> dict:
    mac = (mac or "").strip().replace("-", ":").upper()
    if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
        return {"ok": False, "error": "invalid_mac"}
    raw = bytes.fromhex(mac.replace(":", ""))
    packet = b"\xff" * 6 + raw * 16
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, port))
        s.close()
        return {"ok": True, "mac": mac, "broadcast": broadcast, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}
