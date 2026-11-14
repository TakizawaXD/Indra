#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY ∞ — START SERVICE
#  Creador: Takizawa | Para: Indra
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PID_FILE="$PROJECT_DIR/logs/indra.pid"
LOG_FILE="$PROJECT_DIR/logs/engine.log"

mkdir -p "$PROJECT_DIR/logs"

# Check if already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[!] Indra Infinity is already running with PID $PID."
        echo "[*] Access the Local Dashboard at: http://127.0.0.1:8000"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Acquire wake lock in Termux if available
if command -v termux-wake-lock &> /dev/null; then
    termux-wake-lock
    echo "[*] Termux wake-lock engaged to prevent background sleep."
fi

PY_BIN=$(command -v python3 || command -v python)

echo "[+] Awakening Indra Infinity Engine & Six Eyes Orchestrator..."
nohup "$PY_BIN" -m backend.main > "$LOG_FILE" 2>&1 &
INDRA_PID=$!
echo "$INDRA_PID" > "$PID_FILE"

sleep 2

if kill -0 "$INDRA_PID" 2>/dev/null; then
    echo "======================================================================"
    echo " [+] INDRA INFINITY IS ACTIVE — PID: $INDRA_PID"
    echo " [*] Six Eyes Orchestrator & Infinity Shield: ONLINE"
    echo " [*] Local Dashboard: http://127.0.0.1:8000"
    echo " [*] API Documentation: http://127.0.0.1:8000/docs"
    echo " [*] Log File: logs/engine.log"
    echo "======================================================================"
else
    echo "[-] Failed to start. Showing last logs:"
    cat "$LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi
