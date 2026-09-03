#!/bin/bash
# HARMATTAN Update Script
# Pull latest code, update dependencies, run migrations, restart
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

HARMATTAN_DIR="${HARMATTAN_DIR:-$HOME/harmattan}"
cd "$HARMATTAN_DIR"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  HARMATTAN Update${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Save current version
OLD_VER=$(grep 'VERSION' core/config.py 2>/dev/null | head -1 | cut -d'"' -f2 || echo "unknown")
echo -e "[*] Version actuelle : ${OLD_VER}"

# Pull latest
echo -e "[*] Pull latest..."
if git rev-parse --git-dir > /dev/null 2>&1; then
    git stash 2>/dev/null || true
    git pull --rebase origin main 2>&1 | tail -3
    NEW_VER=$(grep 'VERSION' core/config.py 2>/dev/null | head -1 | cut -d'"' -f2 || echo "unknown")
    echo -e "${GREEN}[✓] Pull OK — ${OLD_VER} → ${NEW_VER}${NC}"
else
    echo -e "${RED}[!] Pas un repo git, skip pull${NC}"
    NEW_VER="$OLD_VER"
fi

# Update venv
echo -e "[*] Update venv..."
VENV_PYTHON="$HARMATTAN_DIR/venv/bin/python"
VENV_PIP="$HARMATTAN_DIR/venv/bin/pip"

if [ ! -d "$HARMATTAN_DIR/venv" ]; then
    echo "[*] Création venv..."
    python3 -m venv venv
fi

"$VENV_PIP" install --upgrade pip setuptools wheel -q 2>/dev/null
"$VENV_PIP" install -r requirements.txt -q 2>&1 | tail -2

# Pre-commit hooks (if available)
if [ -f .pre-commit-config.yaml ]; then
    echo -e "[*] Install pre-commit hooks..."
    "$VENV_PIP" install pre-commit -q 2>/dev/null
    "$HARMATTAN_DIR/venv/bin/pre-commit" install 2>/dev/null || true
fi

# DB migrations (placeholder for future)
echo -e "[*] Check DB schema..."
"$VENV_PYTHON" -c "
import sqlite3, os
db = os.path.join('$HARMATTAN_DIR', 'data', 'harmattan.db')
conn = sqlite3.connect(db)
tables = [r[0] for r in conn.execute('SELECT name FROM sqlite_master WHERE type=\"table\"').fetchall()]
print(f'  Tables: {len(tables)} — {', '.join(tables[:8])}...')
conn.close()
" 2>/dev/null || echo "  (DB check skipped)"

# Kill old instance
echo -e "[*] Stop old instance..."
PORT=$(grep 'PORT' core/config.py 2>/dev/null | head -1 | grep -o '[0-9]*' || echo "8088")
fuser -k "${PORT}/tcp" 2>/dev/null || true
sleep 1

# Clear caches
echo -e "[*] Clear caches..."
rm -rf data/pycache 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Fix permissions (NACF lesson!)
echo -e "[*] Fix permissions..."
chmod -R a+rX static/ 2>/dev/null || true
chmod -R a+rX templates/ 2>/dev/null || true

# Changelog diff
if [ "$OLD_VER" != "$NEW_VER" ] && [ "$OLD_VER" != "unknown" ]; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  Updated: ${OLD_VER} → ${NEW_VER}${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi

echo -e "[*] Lancer avec : cd ~/harmattan && sudo ./harmattan.sh"
echo -e "${GREEN}[✓] Update terminé !${NC}"
