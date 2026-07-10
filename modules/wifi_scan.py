"""
HARMATTAN — Wi‑Fi neighborhood scan via iw / nmcli (best-effort).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime


def _run(cmd: list[str], timeout: float = 12) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def scan_nmcli() -> list[dict]:
    if not shutil.which("nmcli"):
        return []
    code, out, _ = _run(
        ["nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY,IN-USE", "dev", "wifi", "list"],
        timeout=15,
    )
    if code != 0:
        # rescan then list
        _run(["nmcli", "dev", "wifi", "rescan"], timeout=10)
        code, out, _ = _run(
            ["nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY,IN-USE", "dev", "wifi", "list"],
            timeout=15,
        )
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        # nmcli uses : with escaped \:
        parts = []
        buf = ""
        esc = False
        for ch in line:
            if esc:
                buf += ch
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == ":":
                parts.append(buf)
                buf = ""
                continue
            buf += ch
        parts.append(buf)
        while len(parts) < 9:
            parts.append("")
        ssid, bssid, mode, chan, freq, rate, signal, security, in_use = parts[:9]
        rows.append(
            {
                "ssid": ssid or "(hidden)",
                "bssid": bssid,
                "mode": mode,
                "channel": chan,
                "freq": freq,
                "rate": rate,
                "signal": int(signal) if signal.lstrip("-").isdigit() else signal,
                "security": security,
                "in_use": in_use in ("*", "yes", "oui", "1"),
                "source": "nmcli",
            }
        )
    return rows


def scan_iw(iface: str = "wlan0") -> list[dict]:
    if not shutil.which("iw"):
        return []
    code, out, err = _run(["iw", "dev", iface, "scan"], timeout=20)
    if code != 0:
        return []
    rows = []
    cur = {}
    for line in out.splitlines():
        line = line.rstrip()
        if line.startswith("BSS "):
            if cur.get("bssid"):
                rows.append(cur)
            m = re.match(r"BSS\s+([0-9a-fA-F:]{17})", line)
            cur = {
                "bssid": m.group(1) if m else "",
                "ssid": "(hidden)",
                "signal": None,
                "channel": None,
                "freq": None,
                "security": "",
                "source": "iw",
                "in_use": False,
            }
        elif "SSID:" in line and cur:
            cur["ssid"] = line.split("SSID:", 1)[1].strip() or "(hidden)"
        elif "signal:" in line and cur:
            m = re.search(r"signal:\s*([-\d.]+)", line)
            if m:
                try:
                    cur["signal"] = int(float(m.group(1)))
                except ValueError:
                    pass
        elif "freq:" in line and cur:
            m = re.search(r"freq:\s*(\d+)", line)
            if m:
                cur["freq"] = m.group(1)
        elif "primary channel:" in line and cur:
            cur["channel"] = line.split(":")[-1].strip()
        elif "RSN:" in line or "WPA:" in line:
            cur["security"] = (cur.get("security") or "") + line.strip()[:40]
    if cur.get("bssid"):
        rows.append(cur)
    return rows


def scan(iface: str | None = None) -> dict:
    started = datetime.now().isoformat(timespec="seconds")
    aps = scan_nmcli()
    source = "nmcli"
    if not aps and iface:
        aps = scan_iw(iface)
        source = "iw"
    elif not aps:
        # try common ifaces
        for ifc in ("wlan0", "wlp2s0", "wlp3s0", "wifi0"):
            aps = scan_iw(ifc)
            if aps:
                source = f"iw:{ifc}"
                break
    # sort by signal desc
    def _sig(a):
        s = a.get("signal")
        return s if isinstance(s, (int, float)) else -999

    aps = sorted(aps, key=_sig, reverse=True)
    open_aps = [a for a in aps if not a.get("security") or str(a.get("security")).upper() in ("", "--", "OPEN", "NONE")]
    return {
        "started": started,
        "source": source,
        "count": len(aps),
        "open_count": len(open_aps),
        "aps": aps,
        "open_aps": open_aps[:20],
    }
