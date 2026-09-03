#!/bin/bash
# HARMATTAN Git Workflow Setup
# Create branches, install pre-commit, create initial tag
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

HARMATTAN_DIR="${HARMATTAN_DIR:-$HOME/harmattan}"
cd "$HARMATTAN_DIR"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  HARMATTAN Git Setup${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Ensure we're in a git repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "[*] Init git repo..."
    git init
    git add -A
    git commit -m "HARMATTAN v3.22.0 — Major refactoring & improvements"
fi

# Configure git
echo "[*] Configure git..."
git config user.name "Mohamed Adoungouss Ibrahim" 2>/dev/null || true
git config user.email "admin@nacf.cy" 2>/dev/null || true

# Create branches
echo "[*] Create branches..."
CURRENT=$(git branch --show-current 2>/dev/null || echo "main")

if ! git rev-parse --verify develop > /dev/null 2>&1; then
    git checkout -b develop 2>/dev/null || true
    git checkout "$CURRENT" 2>/dev/null || true
    echo -e "${GREEN}[✓] Branch develop created${NC}"
else
    echo "  develop already exists"
fi

# Install pre-commit hooks
echo "[*] Install pre-commit..."
VENV_PIP="$HARMATTAN_DIR/venv/bin/pip"
VENV_BIN="$HARMATTAN_DIR/venv/bin"

if [ -f "$VENV_PIP" ]; then
    "$VENV_PIP" install pre-commit -q 2>/dev/null || true
    "$VENV_BIN/pre-commit" install 2>/dev/null || true
    echo -e "${GREEN}[✓] Pre-commit hooks installed${NC}"
else
    echo "  [!] venv not found, skipping pre-commit install"
fi

# Create tag if not exists
if ! git tag -l "v3.22.0" | grep -q "v3.22.0"; then
    echo "[*] Create tag v3.22.0..."
    git tag -a "v3.22.0" -m "v3.22.0 — Major Refactoring & Improvements" 2>/dev/null || true
    echo -e "${GREEN}[✓] Tag v3.22.0 created${NC}"
else
    echo "  Tag v3.22.0 already exists"
fi

# Show status
echo ""
echo -e "${CYAN}Git Status:${NC}"
git log --oneline -5 2>/dev/null || echo "  (no commits)"
echo ""
git branch -a 2>/dev/null || echo "  (no branches)"
echo ""
git tag -l 2>/dev/null || echo "  (no tags)"

echo -e "${GREEN}[✓] Git setup terminé !${NC}"
