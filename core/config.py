"""
HARMATTAN — Application configuration.
All settings can be overridden via environment variables.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("HARMATTAN_DATA", BASE_DIR / "data"))
REPORTS_DIR = Path(os.environ.get("HARMATTAN_REPORTS", BASE_DIR / "reports"))
DB_PATH = Path(os.environ.get("HARMATTAN_DB", DATA_DIR / "harmattan.db"))
TOKEN_FILE = Path(os.environ.get("HARMATTAN_TOKEN_FILE", DATA_DIR / ".api_token"))
SECRET_FILE = Path(os.environ.get("HARMATTAN_SECRET_FILE", DATA_DIR / ".secret_key"))
# Separate SQLite DB for web users (login/password + roles)
USERS_DB = Path(os.environ.get("HARMATTAN_USERS_DB", DATA_DIR / "users.db"))

HOST = os.environ.get("HARMATTAN_HOST", "127.0.0.1")
PORT = int(os.environ.get("HARMATTAN_PORT", "8088"))
DEBUG = os.environ.get("HARMATTAN_DEBUG", "0") in ("1", "true", "True")

# Auth: if set, every API request (except / and static) needs header X-Harmattan-Token
API_TOKEN = os.environ.get("HARMATTAN_TOKEN", "").strip()
# Auto-generate a session token when none provided (printed at startup)
AUTO_TOKEN = os.environ.get("HARMATTAN_AUTO_TOKEN", "1") in ("1", "true", "True")


def _read_secret_file(path: Path) -> str:
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return ""


def _write_secret_file(path: Path, value: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def load_or_create_token() -> str:
    """Stable API token across restarts (env > file > generate+save)."""
    env = os.environ.get("HARMATTAN_TOKEN", "").strip()
    if env:
        return env
    existing = _read_secret_file(TOKEN_FILE)
    if existing:
        return existing
    token = secrets.token_urlsafe(24)
    _write_secret_file(TOKEN_FILE, token)
    return token


def load_or_create_secret() -> str:
    env = os.environ.get("HARMATTAN_SECRET", "").strip()
    if env:
        return env
    existing = _read_secret_file(SECRET_FILE)
    if existing:
        return existing
    secret = secrets.token_hex(32)
    _write_secret_file(SECRET_FILE, secret)
    return secret


SECRET_KEY = load_or_create_secret()

# Web auth: default admin bootstrap password (used only when no admin user exists).
# If unset, the default admin/admin is created with a forced password change on first login.
HARMATTAN_ADMIN_PASS = os.environ.get("HARMATTAN_ADMIN_PASS", "").strip()

# NVD
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_RATE_DELAY = float(os.environ.get("NVD_RATE_DELAY", "0.6" if NVD_API_KEY else "1.2"))
NVD_CACHE_TTL = int(os.environ.get("NVD_CACHE_TTL", "86400"))  # 24h

# Scan limits
MAX_CONCURRENT_JOBS = int(os.environ.get("HARMATTAN_MAX_JOBS", "3"))
NMAP_TIMEOUT = int(os.environ.get("HARMATTAN_NMAP_TIMEOUT", "600"))
ARP_DEFAULT_TIMEOUT = float(os.environ.get("HARMATTAN_ARP_TIMEOUT", "2.0"))
TRAFFIC_BUFFER = int(os.environ.get("HARMATTAN_TRAFFIC_BUFFER", "5000"))
HISTORY_LIMIT = int(os.environ.get("HARMATTAN_HISTORY_LIMIT", "100"))
ENRICH_WORKERS = int(os.environ.get("HARMATTAN_ENRICH_WORKERS", "16"))

# Allowed nmap custom flags (whitelist)
NMAP_ALLOWED_FLAGS = frozenset({
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-sS", "-sT", "-sU", "-sV", "-sC", "-sA", "-sN", "-sF", "-sX",
    "-O", "-A", "-F", "-Pn", "-n", "-R",
    "-p-", "--top-ports", "-p",
    "--script", "--version-intensity", "--osscan-guess",
    "--max-retries", "--host-timeout", "--min-rate", "--max-rate",
    "-v", "-vv", "--open", "-6",
})

VERSION = "3.22.0"
APP_NAME = "HARMATTAN"
APP_TAGLINE = "Network Intelligence · liquid glass · advanced recon · AI"

# Auth hardening: query-string tokens disabled by default (use header or cookie)
ALLOW_QUERY_TOKEN = os.environ.get("HARMATTAN_ALLOW_QUERY_TOKEN", "0") in ("1", "true", "True")
# Rate limit (requests per minute per client IP); 0 disables
RATE_LIMIT_PER_MIN = int(os.environ.get("HARMATTAN_RATE_LIMIT", "180"))
# Public monitoring endpoints (no auth)
PUBLIC_API_PATHS = frozenset({
    "/api/health",
    "/api/ready",
    "/api/status",
    "/api/preflight",
    "/api/metrics",
})

# SNMP communities to try
SNMP_COMMUNITIES = [
    c.strip()
    for c in os.environ.get("HARMATTAN_SNMP_COMMUNITIES", "public,private").split(",")
    if c.strip()
]


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
