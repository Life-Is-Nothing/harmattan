#!/bin/bash
# Build script for HARMATTAN .deb package
set -euo pipefail

echo "=== Building HARMATTAN Debian Package ==="

# Check dependencies
for cmd in dpkg-buildpackage debuild; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "⚠️  $cmd not found. Install devscripts:"
        echo "   sudo apt-get install devscripts build-essential"
        exit 1
    fi
done

cd "$(dirname "$0")"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -f ../harmattan_*.deb ../harmattan_*.dsc ../harmattan_*.changes
rm -rf debian/.debhelper debian/harmattan/ debian/tmp/

# Build the package
echo "🔨 Building package..."
dpkg-buildpackage -us -uc -b 2>&1 | tee build.log

echo ""
echo "✅ Done!"
echo "   Package: $(ls -1t ../harmattan_*.deb 2>/dev/null | head -1)"
echo ""
echo "Install with:"
echo "   sudo dpkg -i $(ls -1t ../harmattan_*.deb 2>/dev/null | head -1)"
echo "   sudo apt-get install -f"
