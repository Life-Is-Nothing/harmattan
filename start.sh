#!/bin/bash
# HARMATTAN — easy start (wrapper)
set -euo pipefail
cd "$(dirname "$0")"
exec ./harmattan.sh
