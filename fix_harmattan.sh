#!/usr/bin/env bash
# fix_harmattan.sh — repair & bootstrap HARMATTAN environment
# Usage: sudo ./fix_harmattan.sh  (or run as normal user; sudo will be used when needed)

set -euo pipefail
cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}
VENV_DIR=venv
LOGFILE=fix_harmattan.log

echo "[*] Logging to $PWD/$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[*] Starting HARMATTAN fix script"

# Check apt availability
if ! command -v apt-get >/dev/null 2>&1; then
  echo "[!] apt-get not found — this script targets Debian/Ubuntu. Install required packages manually.";
  exit 1
fi

# Update and install system packages
echo "[*] Updating apt and installing system dependencies (requires sudo)"
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO_CMD=sudo
  else
    echo "[!] sudo not available and not running as root. Aborting."; exit 1
  fi
fi

$SUDO_CMD apt-get update -y
$SUDO_CMD apt-get install -y build-essential python3-venv python3-dev libpcap0.8-dev libffi-dev libssl-dev libcap2-bin git

# Ensure install script is executable
chmod +x install.sh || true

# Recreate virtualenv
if [ -d "$VENV_DIR" ]; then
  echo "[*] Removing existing virtualenv: $VENV_DIR"
  rm -rf "$VENV_DIR"
fi

echo "[*] Creating virtualenv with $PYTHON"
$PYTHON -m venv "$VENV_DIR"

# Ensure pip in venv
echo "[*] Upgrading pip, setuptools, wheel in venv"
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

# Install Python requirements
if [ -f requirements.txt ]; then
  echo "[*] Installing Python requirements from requirements.txt"
  "$VENV_DIR/bin/pip" install -r requirements.txt
else
  echo "[!] requirements.txt not found — skipping pip install"
fi

# Apply setcap for raw sockets (non-interactive if HARMATTAN_SETCAP=1 or -y)
APPLY_SETCAP="${HARMATTAN_SETCAP:-}"
if [[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]]; then
  APPLY_SETCAP=1
fi
if [[ -z "$APPLY_SETCAP" && -t 0 ]]; then
  read -rp "[*] Apply setcap CAP_NET_RAW/ADMIN to python? [y/N]: " yn
  [[ "${yn:-N}" =~ ^[Yy] ]] && APPLY_SETCAP=1
fi
if [[ -n "$APPLY_SETCAP" ]]; then
  PY_BIN=$(readlink -f "$VENV_DIR/bin/python")
  echo "[*] Applying setcap to $PY_BIN (and /usr/bin/python3.12)"
  $SUDO_CMD setcap cap_net_raw,cap_net_admin+eip "$PY_BIN" || true
  $SUDO_CMD setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.12 || true
  echo "[*] setcap applied"
else
  echo "[*] Skipping setcap (export HARMATTAN_SETCAP=1 or pass -y)"
fi

# Fix ownership of data/reports/pycache if run after sudo sessions
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
  chown -R "${SUDO_USER}:${SUDO_USER}" data reports modules 2>/dev/null || true
fi

# Ensure pytest for smoke
"$VENV_DIR/bin/pip" install -q pytest setuptools || true
echo "[*] Running targeted tests (tests/test_notifications.py)"
"$VENV_DIR/bin/python" -m pytest -q tests/test_notifications.py || true

echo "[*] Fix script completed. Check $LOGFILE for full output."
echo "Next steps:"
echo "  ./harmattan.sh"
echo "  Open http://127.0.0.1:8088  ·  Hub: http://127.0.0.1:8077"
echo "  Token: cat data/.api_token"

exit 0
