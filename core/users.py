"""
HARMATTAN — Web users store (separate SQLite DB for login/password + roles).

Uses werkzeug.security for password hashing. The token-based API auth in
core/auth.py remains an alternative for machine / API calls and coexists
with this session-based web auth.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, Optional

from werkzeug.security import check_password_hash, generate_password_hash

from core.config import DATA_DIR, HARMATTAN_ADMIN_PASS, USERS_DB, ensure_dirs
from core.logging_setup import get_logger

log = get_logger("harmattan.users")

ROLES = ("admin", "viewer", "scanner")
ROLE_LABELS = {
    "admin": "Administrateur (accès complet)",
    "viewer": "Lecture seule",
    "scanner": "Peut lancer des scans",
}
DEFAULT_ADMIN_USER = "admin"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 min

_local = threading.local()
_init_lock = threading.Lock()
_initialized = False


def _connect() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(str(USERS_DB), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _conn() -> sqlite3.Connection:
    global _initialized
    if not getattr(_local, "conn", None):
        _local.conn = _connect()
    if not _initialized:
        with _init_lock:
            if not _initialized:
                init_users_db(_local.conn)
                _initialized = True
    return _local.conn


@contextmanager
def _cursor() -> Iterator[sqlite3.Cursor]:
    conn = _conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_users_db(conn: Optional[sqlite3.Connection] = None) -> None:
    conn = conn or _conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            must_change INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL,
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
        """
    )
    conn.commit()
    _ensure_default_admin(conn)


def _ensure_default_admin(conn: sqlite3.Connection) -> None:
    """Create the default admin/admin user if no admin exists (bootstrap)."""
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        rows = cur.fetchone()[0] if cur else 0
    except Exception:
        rows = 0
    if rows and rows > 0:
        return
    password = HARMATTAN_ADMIN_PASS or "admin"
    hashed = generate_password_hash(password)
    must_change = 1 if not HARMATTAN_ADMIN_PASS else 0
    now = datetime.now().isoformat(timespec="seconds")
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(username, password_hash, role, must_change, created) "
            "VALUES (?, ?, ?, ?, ?)",
            (DEFAULT_ADMIN_USER, hashed, "admin", must_change, now),
        )
        conn.commit()
        log.info(
            "Bootstrap admin user '%s' created (forced password change=%s)",
            DEFAULT_ADMIN_USER,
            must_change,
        )
    except Exception:
        log.exception("Failed to bootstrap default admin user")


def reset_default_admin() -> str:
    conn = _conn()
    password = HARMATTAN_ADMIN_PASS or "admin"
    hashed = generate_password_hash(password)
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO users (username, password_hash, role, must_change, created) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, "
        "must_change=excluded.must_change",
        (DEFAULT_ADMIN_USER, hashed, "admin", 1 if not HARMATTAN_ADMIN_PASS else 0, now),
    )
    conn.commit()
    return f"Utilisateur admin réinitialisé (mot de passe: {password or 'admin'})"


def create_user(username: str, password: str, role: str = "viewer") -> dict:
    if not username or not password:
        raise ValueError("username et password requis")
    if role not in ROLES:
        raise ValueError(f"role invalide: {role}")
    if len(password) < 4:
        raise ValueError("mot de passe trop court (min 4 caractères)")
    hashed = generate_password_hash(password)
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with _cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, must_change, created) "
                "VALUES (?, ?, ?, 0, ?)",
                (username, hashed, role, now),
            )
            uid = int(cur.lastrowid)
    except sqlite3.IntegrityError:
        raise ValueError(f"Utilisateur '{username}' existe déjà")
    return {"id": uid, "username": username, "role": role}


def list_users() -> list[dict]:
    with _cursor() as cur:
        cur.execute(
            "SELECT id, username, role, must_change, created, last_login "
            "FROM users ORDER BY id"
        )
        return [dict(r) for r in cur.fetchall()]


def get_user(username: str) -> Optional[dict]:
    with _cursor() as cur:
        cur.execute(
            "SELECT id, username, password_hash, role, must_change, created, last_login "
            "FROM users WHERE username=? COLLATE NOCASE",
            (username,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(uid: int) -> Optional[dict]:
    with _cursor() as cur:
        cur.execute(
            "SELECT id, username, password_hash, role, must_change, created, last_login "
            "FROM users WHERE id=?",
            (uid,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def delete_user(user_id: int) -> bool:
    with _cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        return cur.rowcount > 0


def set_role(user_id: int, role: str) -> bool:
    if role not in ROLES:
        raise ValueError(f"role invalide: {role}")
    with _cursor() as cur:
        cur.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        return cur.rowcount > 0


def set_password(user_id: int, new_password: str, clear_must_change: bool = True) -> bool:
    if len(new_password or "") < 4:
        raise ValueError("mot de passe trop court (min 4 caractères)")
    hashed = generate_password_hash(new_password)
    with _cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash=?, must_change=? WHERE id=?",
            (hashed, 0 if clear_must_change else 1, user_id),
        )
        return cur.rowcount > 0


def verify_login(username: str, password: str) -> dict:
    """Verify a username/password. Returns actor dict or raises ValueError."""
    user = get_user(username)
    if not user:
        check_password_hash(generate_password_hash("x"), password)  # constant-time-ish
        raise ValueError("Identifiants invalides.")
    if not check_password_hash(user["password_hash"], password):
        _record_attempt(username, success=False)
        raise ValueError("Identifiants invalides.")
    _record_attempt(username, success=True)
    now = datetime.now().isoformat(timespec="seconds")
    with _cursor() as cur:
        cur.execute(
            "UPDATE users SET last_login=? WHERE id=?", (now, user["id"])
        )
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "must_change": bool(user["must_change"]),
    }


def is_locked_out(username: str) -> Optional[int]:
    """Return remaining lockout seconds, or None if not locked."""
    with _cursor() as cur:
        cur.execute(
            "SELECT attempts, locked_until FROM login_attempts WHERE username=?",
            (username,),
        )
        row = cur.fetchone()
    if not row or not row["locked_until"]:
        return None
    try:
        locked_until = datetime.fromisoformat(row["locked_until"])
    except ValueError:
        return None
    now = datetime.now()
    if now >= locked_until:
        # Reset attempt counter after lockout expiry
        with _cursor() as cur:
            cur.execute(
                "UPDATE login_attempts SET attempts=0, locked_until=NULL WHERE username=?",
                (username,),
            )
        return None
    return int((locked_until - now).total_seconds())


def _record_attempt(username: str, success: bool) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _cursor() as cur:
        cur.execute(
            "SELECT attempts FROM login_attempts WHERE username=?", (username,)
        )
        row = cur.fetchone()
    attempts = (row["attempts"] if row else 0) + 1
    if success:
        attempts = 0
        locked_until = None
    elif attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until = datetime.fromtimestamp(
            datetime.now().timestamp() + LOCKOUT_SECONDS
        ).isoformat(timespec="seconds")
    else:
        locked_until = None
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO login_attempts (username, attempts, locked_until) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET "
            "attempts=excluded.attempts, locked_until=excluded.locked_until",
            (username, attempts, locked_until),
        )


def role_ok(actor_role: str, required: str) -> bool:
    """admin >= scanner >= viewer."""
    rank = {"admin": 3, "scanner": 2, "viewer": 1}
    return rank.get(actor_role, 0) >= rank.get(required, 0)
