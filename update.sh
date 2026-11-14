#!/usr/bin/env bash
# ==============================================================================
#  GOJO INFINITY SECURITY ∞ — UPDATE SCRIPT
# ==============================================================================

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "[*] Checking for Gojo Infinity updates..."

if [ -d ".git" ]; then
    echo "[*] Fetching latest repository updates..."
    git pull origin main || git pull
fi

PY_BIN=$(command -v python3 || command -v python)
echo "[*] Upgrading dependencies..."
$PY_BIN -m pip install -r requirements.txt --upgrade

echo "[*] Applying database migrations if necessary..."
$PY_BIN -c "from backend.database import init_db; init_db()"

echo "[+] Gojo Infinity updated successfully."
