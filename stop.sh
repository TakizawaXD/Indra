#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY ∞ — STOP SERVICE
#  Creador: Takizawa | Para: Indra
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$PROJECT_DIR/logs/indra.pid"
OLD_PID_FILE="$PROJECT_DIR/logs/gojo.pid"

if [ -f "$OLD_PID_FILE" ] && [ ! -f "$PID_FILE" ]; then
    PID_FILE="$OLD_PID_FILE"
fi

if [ ! -f "$PID_FILE" ]; then
    echo "[!] No active Indra Infinity process found (PID file missing)."
    exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    echo "[*] Gracefully stopping Indra Infinity Engine (PID $PID)..."
    kill -15 "$PID"
    for i in {1..10}; do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done
    if kill -0 "$PID" 2>/dev/null; then
        echo "[!] Process did not terminate; sending SIGKILL..."
        kill -9 "$PID"
    fi
    echo "[+] Indra Infinity Engine stopped."
else
    echo "[!] Process $PID was not running."
fi

rm -f "$PID_FILE" "$OLD_PID_FILE"

if command -v termux-wake-unlock &> /dev/null; then
    termux-wake-unlock
fi
