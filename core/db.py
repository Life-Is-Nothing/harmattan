"""
HARMATTAN — SQLite persistence for scans, history, CVE cache.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Optional

from core.config import DB_PATH, HISTORY_LIMIT, NVD_CACHE_TTL, ensure_dirs
from core.logging_setup import get_logger

log = get_logger("harmattan.db")

_local = threading.local()
_init_lock = threading.Lock()
_initialized = False


def _connect() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_conn() -> sqlite3.Connection:
    global _initialized
    if not getattr(_local, "conn", None):
        _local.conn = _connect()
    if not _initialized:
        with _init_lock:
            if not _initialized:
                init_db(_local.conn)
                _initialized = True
    return _local.conn


@contextmanager
def db_cursor() -> Iterator[sqlite3.Cursor]:
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(conn: Optional[sqlite3.Connection] = None) -> None:
    conn = conn or get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            kind TEXT NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            created TEXT NOT NULL,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_cache (
            cache_key TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            expires TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS known_hosts (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            vendor TEXT,
            hostname TEXT,
            first_seen TEXT,
            last_seen TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    conn.commit()
    log.info("Database ready at %s", DB_PATH)


def push_history(kind: str, summary: str) -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO history (time, kind, summary) VALUES (?, ?, ?)",
            (now, kind, summary),
        )
        cur.execute(
            "DELETE FROM history WHERE id NOT IN "
            "(SELECT id FROM history ORDER BY id DESC LIMIT ?)",
            (HISTORY_LIMIT,),
        )
    return {"time": now, "kind": kind, "summary": summary}


def get_history(limit: int = 40) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT time, kind, summary FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def save_scan(kind: str, payload: Any) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (kind, created, payload) VALUES (?, ?, ?)",
            (kind, now, json.dumps(payload, default=str)),
        )
        return int(cur.lastrowid)


def get_last_scan(kind: str) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT payload FROM scans WHERE kind=? ORDER BY id DESC LIMIT 1",
            (kind,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["payload"])


def cve_cache_get(key: str) -> Optional[dict]:
    now = datetime.now().isoformat()
    with db_cursor() as cur:
        cur.execute(
            "SELECT payload FROM cve_cache WHERE cache_key=? AND expires > ?",
            (key, now),
        )
        row = cur.fetchone()
        if row:
            return json.loads(row["payload"])
    return None


def cve_cache_set(key: str, payload: dict, ttl: int = NVD_CACHE_TTL) -> None:
    expires = (datetime.now() + timedelta(seconds=ttl)).isoformat()
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO cve_cache (cache_key, payload, expires) VALUES (?, ?, ?)",
            (key, json.dumps(payload), expires),
        )


def upsert_hosts(hosts: list[dict]) -> list[dict]:
    """Track known hosts; return list of newly seen MACs."""
    now = datetime.now().isoformat(timespec="seconds")
    new_devices = []
    with db_cursor() as cur:
        for h in hosts:
            mac = (h.get("mac") or "").upper()
            if not mac or mac == "FF:FF:FF:FF:FF:FF":
                continue
            cur.execute("SELECT mac, first_seen FROM known_hosts WHERE mac=?", (mac,))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO known_hosts (mac, ip, vendor, hostname, first_seen, last_seen, role) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        mac,
                        h.get("ip"),
                        h.get("vendor"),
                        h.get("hostname"),
                        now,
                        now,
                        h.get("role"),
                    ),
                )
                new_devices.append({**h, "first_seen": now})
            else:
                cur.execute(
                    "UPDATE known_hosts SET ip=?, vendor=?, hostname=?, last_seen=?, role=? WHERE mac=?",
                    (
                        h.get("ip"),
                        h.get("vendor"),
                        h.get("hostname"),
                        now,
                        h.get("role"),
                        mac,
                    ),
                )
    return new_devices


def list_known_hosts() -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT mac, ip, vendor, hostname, first_seen, last_seen, role "
            "FROM known_hosts ORDER BY last_seen DESC"
        )
        return [dict(r) for r in cur.fetchall()]


def export_session_json() -> dict:
    return {
        "exported": datetime.now().isoformat(timespec="seconds"),
        "history": get_history(HISTORY_LIMIT),
        "known_hosts": list_known_hosts(),
        "last_arp": get_last_scan("arp"),
        "last_nmap": get_last_scan("nmap"),
        "last_vuln": get_last_scan("vuln"),
        "last_attack": get_last_scan("attack"),
        "last_network": get_last_scan("network"),
    }
