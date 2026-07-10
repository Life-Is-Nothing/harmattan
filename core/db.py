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
        CREATE TABLE IF NOT EXISTS host_overrides (
            key TEXT PRIMARY KEY,
            role TEXT,
            tags TEXT,
            notes TEXT,
            label TEXT,
            updated TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_key TEXT,
            title TEXT,
            detail TEXT,
            severity TEXT,
            created TEXT
        );
        """
    )
    # migrate known_hosts tags column if missing
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(known_hosts)").fetchall()}
        if "tags" not in cols:
            conn.execute("ALTER TABLE known_hosts ADD COLUMN tags TEXT DEFAULT ''")
        if "notes" not in cols:
            conn.execute("ALTER TABLE known_hosts ADD COLUMN notes TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        ocols = {r[1] for r in conn.execute("PRAGMA table_info(host_overrides)").fetchall()}
        if "label" not in ocols:
            conn.execute("ALTER TABLE host_overrides ADD COLUMN label TEXT DEFAULT ''")
    except Exception:
        pass
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


def list_scans(kind: str | None = None, limit: int = 30) -> list[dict]:
    with db_cursor() as cur:
        if kind:
            cur.execute(
                "SELECT id, kind, created, length(payload) AS size FROM scans "
                "WHERE kind=? ORDER BY id DESC LIMIT ?",
                (kind, limit),
            )
        else:
            cur.execute(
                "SELECT id, kind, created, length(payload) AS size FROM scans "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in cur.fetchall()]


def get_scan(scan_id: int) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT id, kind, created, payload FROM scans WHERE id=?", (scan_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "kind": row["kind"],
            "created": row["created"],
            "payload": json.loads(row["payload"]),
        }


def set_host_override(
    key: str,
    role: str | None = None,
    tags: list[str] | None = None,
    notes: str | None = None,
    label: str | None = None,
) -> dict:
    """key = MAC or IP."""
    key = (key or "").strip().upper() if ":" in (key or "") else (key or "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute("SELECT role, tags, notes, label FROM host_overrides WHERE key=?", (key,))
        row = cur.fetchone()
        old_role = row["role"] if row else None
        old_tags = json.loads(row["tags"]) if row and row["tags"] else []
        old_notes = row["notes"] if row else ""
        try:
            old_label = row["label"] if row else ""
        except (IndexError, KeyError):
            old_label = ""
        new_role = role if role is not None else old_role
        new_tags = tags if tags is not None else old_tags
        new_notes = notes if notes is not None else old_notes
        new_label = label if label is not None else old_label
        cur.execute(
            "INSERT OR REPLACE INTO host_overrides (key, role, tags, notes, label, updated) "
            "VALUES (?,?,?,?,?,?)",
            (key, new_role, json.dumps(new_tags), new_notes or "", new_label or "", now),
        )
        # also update known_hosts role if mac
        if ":" in key and new_role:
            cur.execute("UPDATE known_hosts SET role=? WHERE mac=?", (new_role, key))
    return {
        "key": key,
        "role": new_role,
        "tags": new_tags,
        "notes": new_notes,
        "label": new_label,
        "updated": now,
    }


def get_host_override(key: str) -> Optional[dict]:
    key_u = (key or "").strip().upper() if ":" in (key or "") else (key or "").strip()
    with db_cursor() as cur:
        for k in (key_u, (key or "").strip()):
            cur.execute(
                "SELECT key, role, tags, notes, label, updated FROM host_overrides WHERE key=?",
                (k,),
            )
            row = cur.fetchone()
            if row:
                try:
                    lab = row["label"] or ""
                except (IndexError, KeyError):
                    lab = ""
                return {
                    "key": row["key"],
                    "role": row["role"],
                    "tags": json.loads(row["tags"]) if row["tags"] else [],
                    "notes": row["notes"] or "",
                    "label": lab,
                    "updated": row["updated"],
                }
    return None


def list_overrides() -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT key, role, tags, notes, label, updated FROM host_overrides ORDER BY updated DESC")
        out = []
        for r in cur.fetchall():
            try:
                lab = r["label"] or ""
            except (IndexError, KeyError):
                lab = ""
            out.append(
                {
                    "key": r["key"],
                    "role": r["role"],
                    "tags": json.loads(r["tags"]) if r["tags"] else [],
                    "notes": r["notes"] or "",
                    "label": lab,
                    "updated": r["updated"],
                }
            )
        return out


def delete_host_override(key: str) -> bool:
    key_u = (key or "").strip().upper() if ":" in (key or "") else (key or "").strip()
    with db_cursor() as cur:
        cur.execute("DELETE FROM host_overrides WHERE key=? OR key=?", (key_u, (key or "").strip()))
        return cur.rowcount > 0


def apply_overrides_to_hosts(hosts: list[dict]) -> list[dict]:
    """Applique rôle/tags manuels (MAC puis IP)."""
    if not hosts:
        return hosts
    overs = {o["key"]: o for o in list_overrides()}
    if not overs:
        return hosts
    out = []
    for h in hosts:
        hh = dict(h)
        mac = (hh.get("mac") or "").upper()
        ip = hh.get("ip") or ""
        o = overs.get(mac) or overs.get(ip)
        if o:
            if o.get("role"):
                hh["role"] = o["role"]
                hh["role_override"] = True
            if o.get("tags"):
                hh["tags"] = o["tags"]
            if o.get("notes"):
                hh["notes"] = o["notes"]
            if o.get("label"):
                hh["custom_label"] = o["label"]
        out.append(hh)
    return out


def add_finding(host_key: str, title: str, detail: str = "", severity: str = "info") -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO findings (host_key, title, detail, severity, created) VALUES (?,?,?,?,?)",
            (host_key, title, detail, severity, now),
        )
        fid = cur.lastrowid
    return {"id": fid, "host_key": host_key, "title": title, "detail": detail, "severity": severity, "created": now}


def list_findings(host_key: str | None = None, limit: int = 50) -> list[dict]:
    with db_cursor() as cur:
        if host_key:
            cur.execute(
                "SELECT id, host_key, title, detail, severity, created FROM findings "
                "WHERE host_key=? ORDER BY id DESC LIMIT ?",
                (host_key, limit),
            )
        else:
            cur.execute(
                "SELECT id, host_key, title, detail, severity, created FROM findings "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in cur.fetchall()]


def get_setting(key: str, default: str = "") -> str:
    with db_cursor() as cur:
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )


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
