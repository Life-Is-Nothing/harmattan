#!/bin/bash
set -euo pipefail

# HARMATTAN Desktop — Installation script
# Installs the PyInstaller-built binary, .desktop file, and sets capabilities.

BINARY="${1:-dist/harmattan-desktop}"
INSTALL_DIR="/opt/harmattan"
DESKTOP_FILE="harmattan.desktop"
ICON_SRC="harmattan_gui/resources/icons/app_icon.svg"

echo "== HARMATTAN Desktop Installer =="

if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found at $BINARY"
    echo "   Build it first: pyinstaller --onefile --name harmattan-desktop harmattan_gui/__main__.py"
    exit 1
fi

# Create install directory
echo "📁 Installing to $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"
sudo cp "$BINARY" "$INSTALL_DIR/harmattan-desktop"
sudo chmod 755 "$INSTALL_DIR/harmattan-desktop"

# Copy icon
if [ -f "$ICON_SRC" ]; then
    sudo mkdir -p "$INSTALL_DIR/harmattan_gui/resources/icons"
    sudo cp "$ICON_SRC" "$INSTALL_DIR/harmattan_gui/resources/icons/app_icon.svg"
fi

# Set capabilities for raw socket access (ARP, capture)
echo "🔧 Setting CAP_NET_RAW + CAP_NET_ADMIN capabilities..."
sudo setcap cap_net_raw,cap_net_admin+eip "$INSTALL_DIR/harmattan-desktop" 2>/dev/null || \
    echo "⚠️  setcap failed (non-root?). ARP/capture may require sudo."

# Install .desktop file
echo "🖥️  Installing .desktop file..."
sudo cp "$DESKTOP_FILE" /usr/share/applications/harmattan.desktop
sudo update-desktop-database 2>/dev/null || true

echo ""
echo "✅ HARMATTAN Desktop installed!"
echo "   Launch from application menu or run:"
echo "   $INSTALL_DIR/harmattan-desktop"
echo ""
echo "📝 Note: ARP scanning and traffic capture need either:"
echo "   • sudo (run with sudo)"
echo "   • CAP_NET_RAW capability (already attempted above)"
echo "   • Or run the Flask backend separately with sudo"
