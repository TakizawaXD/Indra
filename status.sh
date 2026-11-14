#!/usr/bin/env bash
# ==============================================================================
#  GOJO INFINITY SECURITY ∞ — STATUS CHECK
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$PROJECT_DIR/logs/gojo.pid"
DB_FILE="$PROJECT_DIR/database/gojo_infinity.db"

echo "=== GOJO INFINITY SECURITY ∞ STATUS ==="

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
