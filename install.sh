#!/usr/bin/env bash
# Installer helper for HARMATTAN (no Docker)
# - creates venv
# - installs requirements
# - optionally applies setcap to venv python for CAP_NET_RAW/CAP_NET_ADMIN

set -euo pipefail
cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}
VENV_DIR=venv

if [ ! -d "$VENV_DIR" ] || [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "[*] Creating virtualenv in $VENV_DIR..."
  $PYTHON -m venv "$VENV_DIR"
fi

PIP="$VENV_DIR/bin/pip"
PY="$VENV_DIR/bin/python"

echo "[*] Upgrading pip and installing requirements..."
"$PIP" install --upgrade pip
"$PIP" install -r requirements.txt

echo "[*] Ensuring data and reports dirs exist..."
mkdir -p data reports

# Optionally apply setcap to allow raw sockets without running as root
if [ "${1:-}" = "--setcap" ] || [ "${APPLY_SETCAP:-}" = "1" ]; then
  if command -v setcap >/dev/null 2>&1; then
    PY_BIN=$(readlink -f "$PY")
    echo "[*] Applying setcap to $PY_BIN (requires root/sudo)..."
    if [ "$(id -u)" -ne 0 ]; then
      sudo setcap cap_net_raw,cap_net_admin+eip "$PY_BIN"
    else
      setcap cap_net_raw,cap_net_admin+eip "$PY_BIN"
    fi
    echo "[*] setcap applied. You can now run ./harmattan.sh without sudo for ARP/capture features."
  else
    echo "[!] setcap not found. Install libcap2-bin (Debian/Ubuntu) or run with sudo to access raw sockets."
  fi
fi

echo "[*] Done. Start with: ./harmattan.sh (use sudo if capture/ARP fails)"
chmod +x ./harmattan.sh
