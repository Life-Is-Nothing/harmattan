#!/bin/bash
# HARMATTAN v3 — Script de lancement professionnel
# ARP + capture trafic : privilèges root ou CAP_NET_RAW recommandés.

set -euo pipefail
cd "$(dirname "$0")"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

PYTHON="./venv/bin/python"
PIP="./venv/bin/pip"

if [ ! -d "venv" ] || [ ! -x "$PYTHON" ]; then
  echo "[*] Premier lancement : création de l'environnement virtuel..."
  python3 -m venv venv
fi

if ! "$PYTHON" -c "import flask" 2>/dev/null; then
  echo "[*] Installation des dépendances Python..."
  "$PIP" install --upgrade pip
  "$PIP" install -r requirements.txt
fi

# Ensure data dirs
mkdir -p data reports

echo "[*] Vérification de nmap..."
if ! command -v nmap &>/dev/null; then
  echo "[!] nmap n'est pas installé. Installez-le avec : sudo apt install nmap"
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "[!] ATTENTION : lancé sans sudo — le scan ARP et la capture de trafic échoueront."
  echo "[!] Relancez avec : sudo ./harmattan.sh"
  echo "[!] Ou : sudo setcap cap_net_raw,cap_net_admin+eip \$(readlink -f ./venv/bin/python)"
fi

# Optional: export token for scripts
if [ -n "${HARMATTAN_TOKEN:-}" ]; then
  echo "[*] Token API fourni via HARMATTAN_TOKEN"
fi

HOST="${HARMATTAN_HOST:-127.0.0.1}"
PORT="${HARMATTAN_PORT:-8088}"
echo "[*] Démarrage de HARMATTAN v3 sur http://${HOST}:${PORT} ..."
exec "$PYTHON" app.py
