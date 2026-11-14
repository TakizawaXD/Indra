#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY ∞ — STATUS CHECK
#  Creador: Takizawa | Para: Indra
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$PROJECT_DIR/logs/indra.pid"
OLD_PID_FILE="$PROJECT_DIR/logs/gojo.pid"
if [ -f "$OLD_PID_FILE" ] && [ ! -f "$PID_FILE" ]; then
    PID_FILE="$OLD_PID_FILE"
fi

DB_FILE="$PROJECT_DIR/database/gojo_infinity.db"

echo "=== INDRA INFINITY SECURITY ∞ STATUS ==="

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[STATUS] Active & Running (PID: $PID)"
        echo "[PORT]   http://127.0.0.1:8000"
    else
        echo "[STATUS] Stale PID file found. Process $PID is not running."
    fi
else
    echo "[STATUS] Stopped"
fi

if [ -f "$DB_FILE" ]; then
    DB_SIZE=$(du -h "$DB_FILE" 2>/dev/null | cut -f1)
    echo "[DATABASE] Online ($DB_FILE, Size: $DB_SIZE)"
else
    echo "[DATABASE] Not yet initialized."
fi

echo "========================================"
