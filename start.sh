#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY - TERMINAL INTERACTIVA
#  Creador: Takizawa | Para: Indra
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Acquire wake lock in Termux if available
if command -v termux-wake-lock &> /dev/null; then
    termux-wake-lock
fi

# Auto-actualizacion automatica desde GitHub
if [ -d ".git" ]; then
    git pull origin main --quiet 2>/dev/null || true
fi

PY_BIN=$(command -v python3 || command -v python)
exec "$PY_BIN" -m terminal.shell "$@"
