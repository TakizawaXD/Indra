#!/usr/bin/env bash
# ==============================================================================
#  GOJO INFINITY SECURITY ∞ — BACKUP UTILITY
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TARGET_ARCHIVE="$BACKUP_DIR/gojo_backup_$TIMESTAMP.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "[*] Creating atomic backup of Gojo Infinity Database and Configurations..."

tar -czf "$TARGET_ARCHIVE" \
    --exclude="backups" \
    --exclude="__pycache__" \
    --exclude="*.pyc" \
    --exclude="logs/*.log" \
    -C "$PROJECT_DIR" database config quarantine reports 2>/dev/null || true

if [ -f "$TARGET_ARCHIVE" ]; then
    SIZE=$(du -h "$TARGET_ARCHIVE" | cut -f1)
    echo "[+] Backup generated successfully: $TARGET_ARCHIVE ($SIZE)"
else
    echo "[-] Backup creation failed."
    exit 1
fi
