#!/bin/bash
# HARMATTAN Network — lance avec sudo pour ARP / capture trafic
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Re-exec as root if needed (Network requires CAP_NET_RAW for full features)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  if [ "${HARMATTAN_NO_SUDO:-0}" = "1" ]; then
    echo "[!] HARMATTAN_NO_SUDO=1 — lancement sans root (ARP/capture limités)"
  else
    echo "[*] Élévation sudo requise pour HARMATTAN Network (ARP + capture)…"
    # Preserve env useful for the suite
    exec sudo -E env \
      "HOME=${HOME:-/home/lifeisnothing}" \
      "PATH=$PATH" \
      "HARMATTAN_TOKEN=${HARMATTAN_TOKEN:-}" \
      "HARMATTAN_HUB_URL=${HARMATTAN_HUB_URL:-}" \
      "HARMATTAN_HUB_TOKEN=${HARMATTAN_HUB_TOKEN:-}" \
      "HARMATTAN_HOST=${HARMATTAN_HOST:-127.0.0.1}" \
      "HARMATTAN_PORT=${HARMATTAN_PORT:-8088}" \
      "PYTHONDONTWRITEBYTECODE=1" \
      "PYTHONUNBUFFERED=1" \
      "SCAPY_USE_PCAP=0" \
      bash "$SCRIPT_DIR/harmattan.sh" "$@"
  fi
fi

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export SCAPY_USE_PCAP=0
export PYTHONPYCACHEPREFIX="${SCRIPT_DIR}/data/pycache"
# Keep user-owned data when run as root
REAL_USER="${SUDO_USER:-lifeisnothing}"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo /home/lifeisnothing)"
export HOME="${REAL_HOME}"

mkdir -p "$PYTHONPYCACHEPREFIX" data reports

PYTHON="$SCRIPT_DIR/venv/bin/python"
PIP="$SCRIPT_DIR/venv/bin/pip"

if [ ! -d "venv" ] || [ ! -x "$PYTHON" ]; then
  echo "[*] Création venv…"
  python3 -m venv venv
fi

if ! "$PYTHON" -c "import flask" 2>/dev/null; then
  echo "[*] Installation dépendances…"
  "$PIP" install --upgrade pip setuptools wheel
  "$PIP" install -r requirements.txt
fi

if ! command -v nmap &>/dev/null; then
  echo "[!] nmap manquant : apt install nmap"
fi

if [ -z "${HARMATTAN_TOKEN:-}" ] && [ -f data/.api_token ]; then
  HARMATTAN_TOKEN="$(tr -d '[:space:]' < data/.api_token)"
  export HARMATTAN_TOKEN
  echo "[*] Token chargé depuis data/.api_token"
fi

HOST="${HARMATTAN_HOST:-127.0.0.1}"
PORT="${HARMATTAN_PORT:-8088}"

if ss -ltn "sport = :${PORT}" 2>/dev/null | grep -q ":${PORT}"; then
  # As root (or forced), free the port so relaunch works
  if [ "${EUID:-$(id -u)}" -eq 0 ] || [ "${HARMATTAN_REPLACE:-0}" = "1" ]; then
    echo "[*] Port ${PORT} occupé — arrêt de l'ancienne instance…"
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    sleep 0.6
    if ss -ltn "sport = :${PORT}" 2>/dev/null | grep -q ":${PORT}"; then
      echo "[!] Impossible de libérer :${PORT}"
      exit 1
    fi
    echo "[*] Port ${PORT} libre."
  else
    echo "[!] Port ${PORT} déjà occupé."
    echo "[!] sudo fuser -k ${PORT}/tcp   puis   sudo ~/harmattan/harmattan.sh"
    echo "[!] ou :  HARMATTAN_REPLACE=1 sudo -E ~/harmattan/harmattan.sh"
    exit 1
  fi
fi

# Ensure data dir stays usable by user after root run
chown -R "${REAL_USER}:${REAL_USER}" data reports 2>/dev/null || true

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  echo "[*] HARMATTAN Network (root) → http://${HOST}:${PORT}"
else
  echo "[*] HARMATTAN Network (user) → http://${HOST}:${PORT}"
fi
exec "$PYTHON" "$SCRIPT_DIR/app.py"
