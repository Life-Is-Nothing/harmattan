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

HOST = os.environ.get("HARMATTAN_HOST", "127.0.0.1")
PORT = int(os.environ.get("HARMATTAN_PORT", "8088"))
DEBUG = os.environ.get("HARMATTAN_DEBUG", "0") in ("1", "true", "True")

# Auth: if set, every API request (except / and static) needs header X-Harmattan-Token
API_TOKEN = os.environ.get("HARMATTAN_TOKEN", "").strip()
# Auto-generate a session token when none provided (printed at startup)
AUTO_TOKEN = os.environ.get("HARMATTAN_AUTO_TOKEN", "1") in ("1", "true", "True")

SECRET_KEY = os.environ.get("HARMATTAN_SECRET", secrets.token_hex(32))

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

VERSION = "3.9.0"
APP_NAME = "HARMATTAN"
APP_TAGLINE = "Network Intelligence — L0p4Map parity · multi-hop · default-cred · WOL"

# SNMP communities to try
SNMP_COMMUNITIES = [
    c.strip()
    for c in os.environ.get("HARMATTAN_SNMP_COMMUNITIES", "public,private").split(",")
    if c.strip()
]


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
