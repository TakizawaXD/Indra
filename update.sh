#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY - ACTUALIZADOR AUTOMATICO (LINUX / TERMUX)
#  Creador: Takizawa | Para: Indra
# ==============================================================================

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "======================================================================"
echo " [*] COMPROBANDO ACTUALIZACIONES DESDE GITHUB (TakizawaXD/Indra)"
echo "======================================================================"

if [ -d ".git" ]; then
    echo "[*] Sincronizando codigo fuente con git pull origin main..."
    git pull origin main || git pull || true
fi

PY_BIN=$(command -v python3 || command -v python)
echo "[*] Sincronizando dependencias de Python (requirements.txt)..."
PY_BIN="$PY_BIN" bash ./install_deps.sh --upgrade

echo "======================================================================"
echo " [+] INDRA INFINITY SECURITY ACTUALIZADO EXITOSAMENTE"
echo "======================================================================"
