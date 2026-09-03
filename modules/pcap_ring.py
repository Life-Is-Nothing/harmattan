"""
HARMATTAN — PCAP ring buffer on disk (rotation by size / file count).
Works with scapy when available; otherwise stores packet meta JSONL.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from core.config import DATA_DIR
from core.logging_setup import get_logger

log = get_logger("harmattan.pcap_ring")

RING_DIR = Path(os.environ.get("HARMATTAN_PCAP_DIR", DATA_DIR / "pcap_ring"))
MAX_FILES = int(os.environ.get("HARMATTAN_PCAP_MAX_FILES", "8"))
MAX_BYTES = int(os.environ.get("HARMATTAN_PCAP_MAX_BYTES", str(50 * 1024 * 1024)))  # 50MB total budget

_lock = threading.Lock()
_writer_open = False
_current_path: Optional[Path] = None
_current_size = 0
_packet_count = 0
_meta_path: Optional[Path] = None


def ensure_ring_dir() -> Path:
    RING_DIR.mkdir(parents=True, exist_ok=True)
    return RING_DIR


def status() -> dict[str, Any]:
    ensure_ring_dir()
    files = sorted(RING_DIR.glob("*.pcap")) + sorted(RING_DIR.glob("*.jsonl"))
    total = sum(f.stat().st_size for f in files if f.is_file())
    return {
        "ok": True,
        "dir": str(RING_DIR),
        "files": [
            {"name": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime}
            for f in sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
        ],
        "total_bytes": total,
        "max_bytes": MAX_BYTES,
        "max_files": MAX_FILES,
        "writing": _writer_open,
        "current": str(_current_path) if _current_path else None,
        "packet_count_session": _packet_count,
    }


def _rotate_if_needed(add_bytes: int = 0) -> None:
    global _current_path, _current_size, _meta_path
    ensure_ring_dir()
    files = sorted(
        list(RING_DIR.glob("*.pcap")) + list(RING_DIR.glob("*.jsonl")),
        key=lambda p: p.stat().st_mtime,
    )
    total = sum(f.stat().st_size for f in files) + add_bytes
    while (len(files) > MAX_FILES or total > MAX_BYTES) and files:
        old = files.pop(0)
        try:
            total -= old.stat().st_size
            old.unlink(missing_ok=True)
            # companion meta
            meta = old.with_suffix(old.suffix + ".meta")
            if meta.is_file():
                meta.unlink(missing_ok=True)
        except OSError as e:
            log.debug("rotate unlink: %s", e)


def open_writer(prefix: str = "capture") -> dict:
    """Open a new ring segment (jsonl meta always; pcap if scapy wrpcap available later)."""
    global _writer_open, _current_path, _current_size, _packet_count, _meta_path
    with _lock:
        _rotate_if_needed()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        _meta_path = ensure_ring_dir() / f"{prefix}_{ts}.jsonl"
        _current_path = _meta_path
        _current_size = 0
        _packet_count = 0
        _writer_open = True
        _meta_path.write_text("", encoding="utf-8")
        return {"ok": True, "path": str(_meta_path)}


def close_writer() -> dict:
    global _writer_open
    with _lock:
        _writer_open = False
        return {"ok": True, "path": str(_current_path) if _current_path else None, "packets": _packet_count}


def append_packet(meta: dict) -> bool:
    """Append one packet metadata line to the current ring file."""
    global _current_size, _packet_count
    with _lock:
        if not _writer_open or not _meta_path:
            return False
        line = json.dumps(meta, default=str, ensure_ascii=False) + "\n"
        raw = line.encode("utf-8")
        try:
            with open(_meta_path, "ab") as f:
                f.write(raw)
            _current_size += len(raw)
            _packet_count += 1
            if _current_size > MAX_BYTES // max(2, MAX_FILES):
                # rotate segment
                open_writer(prefix="capture")
            else:
                _rotate_if_needed(0)
            return True
        except OSError as e:
            log.debug("append_packet: %s", e)
            return False


def search(
    ip: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Search ring JSONL files by IP / port / protocol."""
    ensure_ring_dir()
    hits: list[dict] = []
    files = sorted(RING_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    ip = (ip or "").strip() or None
    protocol = (protocol or "").strip().lower() or None
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if len(hits) >= limit:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ip:
                        src = str(obj.get("src") or obj.get("src_ip") or "")
                        dst = str(obj.get("dst") or obj.get("dst_ip") or "")
                        if ip not in (src, dst) and ip not in src and ip not in dst:
                            continue
                    if port is not None:
                        sp = obj.get("sport") or obj.get("src_port")
                        dp = obj.get("dport") or obj.get("dst_port")
                        try:
                            if int(port) not in (int(sp or -1), int(dp or -1)):
                                continue
                        except (TypeError, ValueError):
                            continue
                    if protocol:
                        proto = str(obj.get("proto") or obj.get("protocol") or "").lower()
                        if protocol not in proto:
                            continue
                    obj["_file"] = fpath.name
                    hits.append(obj)
        except OSError:
            continue
        if len(hits) >= limit:
            break
    return {"ok": True, "count": len(hits), "hits": hits, "query": {"ip": ip, "port": port, "protocol": protocol}}


def ingest_from_capture(packets: list[dict], open_if_needed: bool = True) -> int:
    """Bulk ingest dissected packet dicts from traffic_analyzer."""
    if open_if_needed and not _writer_open:
        open_writer()
    n = 0
    for p in packets:
        meta = {
            "ts": p.get("time") or p.get("ts") or time.time(),
            "src": p.get("src") or p.get("src_ip"),
            "dst": p.get("dst") or p.get("dst_ip"),
            "sport": p.get("sport") or p.get("src_port"),
            "dport": p.get("dport") or p.get("dst_port"),
            "proto": p.get("protocol") or p.get("proto"),
            "length": p.get("length") or p.get("len"),
            "info": (p.get("info") or "")[:200],
        }
        if append_packet(meta):
            n += 1
    return n


def clear_ring() -> dict:
    ensure_ring_dir()
    n = 0
    for f in list(RING_DIR.glob("*")):
        try:
            f.unlink()
            n += 1
        except OSError:
            pass
    return {"ok": True, "deleted": n}
