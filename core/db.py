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
        -- Notifications persisted for UI and audit
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            type TEXT NOT NULL,
            payload TEXT NOT NULL
        );
        -- Simple alert rules: name, type to match, condition (json) and webhook optional
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            condition TEXT,
            webhook TEXT,
            created TEXT
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER DEFAULT 0,
            message TEXT,
            error TEXT,
            created TEXT,
            started TEXT,
            finished TEXT,
            result TEXT
        );
        CREATE TABLE IF NOT EXISTS ignored_hosts (
            key TEXT PRIMARY KEY,
            reason TEXT DEFAULT '',
            created TEXT
        );
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            created TEXT NOT NULL,
            fingerprint TEXT,
            is_active INTEGER DEFAULT 0,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            events TEXT DEFAULT '*',
            enabled INTEGER DEFAULT 1,
            created TEXT
        );
        CREATE TABLE IF NOT EXISTS asset_groups (
            name TEXT PRIMARY KEY,
            description TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            created TEXT
        );
        -- NEW: Export history
        CREATE TABLE IF NOT EXISTS exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            format TEXT NOT NULL,
            scope TEXT DEFAULT '',
            created TEXT NOT NULL,
            file_path TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}'
        );
        -- NEW: Plugin registry
        CREATE TABLE IF NOT EXISTS plugins (
            name TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            description TEXT DEFAULT '',
            author TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            path TEXT DEFAULT '',
            config TEXT DEFAULT '{}',
            installed_at TEXT
        );
        -- NEW: Multi-canal notification channels
        CREATE TABLE IF NOT EXISTS notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            canal TEXT NOT NULL,
            label TEXT NOT NULL,
            config TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            events TEXT DEFAULT '*',
            created TEXT
        );
        -- NEW: API keys for versioned API access
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT '',
            role TEXT DEFAULT 'readonly',
            revoked INTEGER DEFAULT 0,
            created TEXT,
            last_used TEXT
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
    """Track known hosts; return list of newly seen MACs. Skips ignored hosts."""
    now = datetime.now().isoformat(timespec="seconds")
    new_devices = []
    ignored = ignored_key_set()
    with db_cursor() as cur:
        for h in hosts:
            mac = (h.get("mac") or "").upper()
            ip = (h.get("ip") or "").strip()
            if mac in ignored or ip in ignored:
                continue
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


def _norm_host_key(key: str) -> str:
    key = (key or "").strip()
    if ":" in key:
        return key.upper()
    return key


def ignored_key_set() -> set[str]:
    with db_cursor() as cur:
        cur.execute("SELECT key FROM ignored_hosts")
        return {r["key"] for r in cur.fetchall()}


def list_ignored_hosts() -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT key, reason, created FROM ignored_hosts ORDER BY created DESC")
        return [dict(r) for r in cur.fetchall()]


def add_ignored_host(key: str, reason: str = "") -> dict:
    key = _norm_host_key(key)
    if not key:
        raise ValueError("missing_key")
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO ignored_hosts (key, reason, created) VALUES (?,?,?)",
            (key, reason or "", now),
        )
    return {"key": key, "reason": reason or "", "created": now}


def remove_ignored_host(key: str) -> bool:
    key = _norm_host_key(key)
    with db_cursor() as cur:
        cur.execute("DELETE FROM ignored_hosts WHERE key=?", (key,))
        return cur.rowcount > 0


def clear_ignored_hosts() -> int:
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM ignored_hosts")
        n = int(cur.fetchone()["n"])
        cur.execute("DELETE FROM ignored_hosts")
        return n


def is_ignored_host(host: dict) -> bool:
    ignored = ignored_key_set()
    mac = (host.get("mac") or "").upper()
    ip = (host.get("ip") or "").strip()
    return bool((mac and mac in ignored) or (ip and ip in ignored))


def filter_ignored_hosts(hosts: list[dict]) -> list[dict]:
    if not hosts:
        return hosts
    ignored = ignored_key_set()
    if not ignored:
        return hosts
    out = []
    for h in hosts:
        mac = (h.get("mac") or "").upper()
        ip = (h.get("ip") or "").strip()
        if mac in ignored or ip in ignored:
            continue
        out.append(h)
    return out


def delete_known_host(mac: str) -> bool:
    mac = (mac or "").strip().upper()
    if not mac:
        return False
    with db_cursor() as cur:
        cur.execute("DELETE FROM known_hosts WHERE mac=?", (mac,))
        return cur.rowcount > 0


def clear_known_hosts() -> int:
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM known_hosts")
        n = int(cur.fetchone()["n"])
        cur.execute("DELETE FROM known_hosts")
        return n


def delete_scan(scan_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return cur.rowcount > 0


def clear_scans(kind: str | None = None) -> int:
    with db_cursor() as cur:
        if kind:
            cur.execute("SELECT COUNT(*) AS n FROM scans WHERE kind=?", (kind,))
            n = int(cur.fetchone()["n"])
            cur.execute("DELETE FROM scans WHERE kind=?", (kind,))
        else:
            cur.execute("SELECT COUNT(*) AS n FROM scans")
            n = int(cur.fetchone()["n"])
            cur.execute("DELETE FROM scans")
        return n


def clear_history() -> int:
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM history")
        n = int(cur.fetchone()["n"])
        cur.execute("DELETE FROM history")
        return n


def delete_finding(finding_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM findings WHERE id=?", (finding_id,))
        return cur.rowcount > 0


def clear_findings(host_key: str | None = None) -> int:
    with db_cursor() as cur:
        if host_key:
            cur.execute("SELECT COUNT(*) AS n FROM findings WHERE host_key=?", (host_key,))
            n = int(cur.fetchone()["n"])
            cur.execute("DELETE FROM findings WHERE host_key=?", (host_key,))
        else:
            cur.execute("SELECT COUNT(*) AS n FROM findings")
            n = int(cur.fetchone()["n"])
            cur.execute("DELETE FROM findings")
        return n


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


# ---------------------------------------------------------------------------
# Baselines (drift detection)
# ---------------------------------------------------------------------------
def save_baseline(label: str, payload: dict, activate: bool = True) -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    fp = payload.get("fingerprint") or ""
    with db_cursor() as cur:
        if activate:
            cur.execute("UPDATE baselines SET is_active=0")
        cur.execute(
            "INSERT INTO baselines (label, created, fingerprint, is_active, payload) VALUES (?,?,?,?,?)",
            (label, now, fp, 1 if activate else 0, json.dumps(payload, default=str)),
        )
        bid = int(cur.lastrowid)
    return {"id": bid, "label": label, "created": now, "fingerprint": fp, "active": activate}


def list_baselines(limit: int = 20) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, label, created, fingerprint, is_active FROM baselines ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "id": r["id"],
                "label": r["label"],
                "created": r["created"],
                "fingerprint": r["fingerprint"],
                "active": bool(r["is_active"]),
            }
            for r in cur.fetchall()
        ]


def get_baseline(baseline_id: int | None = None, active: bool = False) -> Optional[dict]:
    with db_cursor() as cur:
        if active:
            cur.execute(
                "SELECT id, label, created, fingerprint, is_active, payload FROM baselines "
                "WHERE is_active=1 ORDER BY id DESC LIMIT 1"
            )
        elif baseline_id is not None:
            cur.execute(
                "SELECT id, label, created, fingerprint, is_active, payload FROM baselines WHERE id=?",
                (baseline_id,),
            )
        else:
            cur.execute(
                "SELECT id, label, created, fingerprint, is_active, payload FROM baselines "
                "ORDER BY id DESC LIMIT 1"
            )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "label": row["label"],
            "created": row["created"],
            "fingerprint": row["fingerprint"],
            "active": bool(row["is_active"]),
            "payload": json.loads(row["payload"]),
        }


def set_active_baseline(baseline_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute("SELECT id FROM baselines WHERE id=?", (baseline_id,))
        if not cur.fetchone():
            return False
        cur.execute("UPDATE baselines SET is_active=0")
        cur.execute("UPDATE baselines SET is_active=1 WHERE id=?", (baseline_id,))
        return True


def delete_baseline(baseline_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM baselines WHERE id=?", (baseline_id,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Webhooks (Discord / Slack / Telegram / generic)
# ---------------------------------------------------------------------------
def add_webhook(name: str, url: str, events: str = "*") -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO webhooks (name, url, events, enabled, created) VALUES (?,?,?,?,?)",
            (name, url, events or "*", 1, now),
        )
        wid = int(cur.lastrowid)
    return {"id": wid, "name": name, "url": url, "events": events or "*", "enabled": True, "created": now}


def list_webhooks() -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT id, name, url, events, enabled, created FROM webhooks ORDER BY id DESC")
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "url": r["url"],
                "events": r["events"],
                "enabled": bool(r["enabled"]),
                "created": r["created"],
            }
            for r in cur.fetchall()
        ]


def delete_webhook(webhook_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM webhooks WHERE id=?", (webhook_id,))
        return cur.rowcount > 0


def set_webhook_enabled(webhook_id: int, enabled: bool) -> bool:
    with db_cursor() as cur:
        cur.execute("UPDATE webhooks SET enabled=? WHERE id=?", (1 if enabled else 0, webhook_id))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Asset groups / tags helpers
# ---------------------------------------------------------------------------
def tags_summary() -> dict:
    """Count tags from host_overrides."""
    counts: dict[str, int] = {}
    for o in list_overrides():
        for t in o.get("tags") or []:
            t = str(t).strip()
            if t:
                counts[t] = counts.get(t, 0) + 1
    return counts


def hosts_by_tag(tag: str) -> list[dict]:
    tag = (tag or "").strip().lower()
    out = []
    for o in list_overrides():
        tags = [str(t).lower() for t in (o.get("tags") or [])]
        if tag in tags:
            out.append(o)
    return out


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


# ---------------------------------------------------------------------------
# Notifications & Alert rules (persistent wrappers)
# ---------------------------------------------------------------------------
def save_notification(event_type: str, payload: dict) -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO notifications (time, type, payload) VALUES (?, ?, ?)",
            (now, event_type, json.dumps(payload, default=str)),
        )
        nid = cur.lastrowid
    return {"id": nid, "time": now, "type": event_type, "payload": payload}


def list_notifications(limit: int = 100) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, time, type, payload FROM notifications ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        out = []
        for r in cur.fetchall():
            out.append({"id": r["id"], "time": r["time"], "type": r["type"], "payload": json.loads(r["payload"])})
        return out


def add_alert_rule(name: str, event_type: str, condition: str | None = None, webhook: str | None = None) -> dict:
    now = datetime.now().isoformat(timespec="seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO alert_rules (name, event_type, condition, webhook, created) VALUES (?,?,?,?,?)",
            (name, event_type, condition or "", webhook or "", now),
        )
        rid = cur.lastrowid
    return {"id": rid, "name": name, "event_type": event_type, "condition": condition or "", "webhook": webhook or "", "created": now}


def list_alert_rules() -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT id, name, event_type, condition, webhook, created FROM alert_rules ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]


def upsert_job(job: dict) -> None:
    """Persist job metadata (and optional truncated result)."""
    result = job.get("result")
    result_s = None
    if result is not None:
        result_s = json.dumps(result, default=str)
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO jobs (id, kind, status, progress, message, error, created, started, finished, result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              kind=excluded.kind,
              status=excluded.status,
              progress=excluded.progress,
              message=excluded.message,
              error=excluded.error,
              started=excluded.started,
              finished=excluded.finished,
              result=COALESCE(excluded.result, jobs.result)
            """,
            (
                job.get("id"),
                job.get("kind") or "",
                job.get("status") or "",
                int(job.get("progress") or 0),
                job.get("message") or "",
                job.get("error"),
                job.get("created"),
                job.get("started"),
                job.get("finished"),
                result_s,
            ),
        )
        # keep last 100 jobs
        cur.execute(
            "DELETE FROM jobs WHERE id NOT IN (SELECT id FROM jobs ORDER BY created DESC LIMIT 100)"
        )


def list_jobs(limit: int = 50) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, kind, status, progress, message, error, created, started, finished, result "
            "FROM jobs ORDER BY created DESC LIMIT ?",
            (limit,),
        )
        out = []
        for r in cur.fetchall():
            d = dict(r)
            if d.get("result"):
                try:
                    d["result"] = json.loads(d["result"])
                except Exception:
                    d["result"] = None
            else:
                d["result"] = None
            out.append(d)
        return out


def get_job(job_id: str) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, kind, status, progress, message, error, created, started, finished, result "
            "FROM jobs WHERE id=?",
            (job_id,),
        )
        r = cur.fetchone()
        if not r:
            return None
        d = dict(r)
        if d.get("result"):
            try:
                d["result"] = json.loads(d["result"])
            except Exception:
                d["result"] = None
        return d


# ── Export history ──────────────────────────────────────────────


def save_export(format_: str, scope: str, file_path: str, size: int = 0, metadata: dict | None = None) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO exports (format, scope, created, file_path, size, metadata) VALUES (?,?,?,?,?,?)",
            (format_, scope, datetime.now().isoformat(), file_path, size, json.dumps(metadata or {})),
        )
        return cur.lastrowid or 0


def list_exports(limit: int = 50) -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM exports ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


# ── Notification channels ──────────────────────────────────────


def save_notification_channel(canal: str, label: str, config: dict, events: str = "*", enabled: int = 1) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO notification_channels (canal, label, config, events, enabled, created) VALUES (?,?,?,?,?,?)",
            (canal, label, json.dumps(config), events, enabled, datetime.now().isoformat()),
        )
        return cur.lastrowid or 0


def update_notification_channel(ch_id: int, **kwargs) -> None:
    fields = []
    vals = []
    for k, v in kwargs.items():
        if k in ("label", "config", "events", "enabled"):
            if k == "config" and isinstance(v, dict):
                v = json.dumps(v)
            fields.append(f"{k}=?")
            vals.append(v)
    if not fields:
        return
    vals.append(ch_id)
    with db_cursor() as cur:
        cur.execute(f"UPDATE notification_channels SET {','.join(fields)} WHERE id=?", vals)


def list_notification_channels(enabled_only: bool = False) -> list[dict]:
    with db_cursor() as cur:
        if enabled_only:
            cur.execute("SELECT * FROM notification_channels WHERE enabled=1 ORDER BY canal")
        else:
            cur.execute("SELECT * FROM notification_channels ORDER BY canal")
        return [dict(r) for r in cur.fetchall()]


def delete_notification_channel(ch_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("DELETE FROM notification_channels WHERE id=?", (ch_id,))


# ── Plugin registry ────────────────────────────────────────────


def register_plugin(name: str, version: str, description: str = "", author: str = "",
                    path: str = "", config: dict | None = None) -> None:
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO plugins (name, version, description, author, enabled, path, config, installed_at) "
            "VALUES (?,?,?,?,1,?,?,?)",
            (name, version, description, author, path, json.dumps(config or {}), datetime.now().isoformat()),
        )


def list_plugins(enabled_only: bool = False) -> list[dict]:
    with db_cursor() as cur:
        if enabled_only:
            cur.execute("SELECT * FROM plugins WHERE enabled=1 ORDER BY name")
        else:
            cur.execute("SELECT * FROM plugins ORDER BY name")
        return [dict(r) for r in cur.fetchall()]


def toggle_plugin(name: str, enabled: bool) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE plugins SET enabled=? WHERE name=?", (1 if enabled else 0, name))


def delete_plugin(name: str) -> None:
    with db_cursor() as cur:
        cur.execute("DELETE FROM plugins WHERE name=?", (name,))


# ── API Keys ───────────────────────────────────────────────────


def create_api_key(key: str, label: str = "", role: str = "readonly") -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO api_keys (key, label, role, created) VALUES (?,?,?,?)",
            (key, label, role, datetime.now().isoformat()),
        )
        return cur.lastrowid or 0


def list_api_keys() -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM api_keys ORDER BY created DESC")
        return [dict(r) for r in cur.fetchall()]


def revoke_api_key(key_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))