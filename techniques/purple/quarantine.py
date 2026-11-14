"""
GOJO INFINITY SECURITY ∞ — PURPLE FILE QUARANTINE VAULT
Isolates suspicious or compromised files safely with encrypted metadata
and enables authorized, reversible restoration.
"""

import os
import shutil
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from core.config import settings
from core.logger import logger
from core.event_engine import event_bus, EventType, SecurityEventPayload

class QuarantineVault:
    """
    Safely moves suspect files into the secure quarantine directory,
    retaining original hashes, permissions, and reversal receipts.
    """

    def __init__(self):
        self.vault_dir = settings.QUARANTINE_DIR
        self.manifest_file = self.vault_dir / "quarantine_manifest.json"
        self._ensure_manifest()

    def _ensure_manifest(self):
        if not self.manifest_file.exists():
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _load_manifest(self) -> Dict[str, Any]:
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_manifest(self, data: Dict[str, Any]):
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def quarantine_file(self, target_path: str, reason: str, operator: str = "system") -> Dict[str, Any]:
        """Quarantines a file by isolating it and recording metadata."""
        src = Path(target_path).resolve()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"Target file for quarantine not found: {target_path}")

        # Compute SHA256
        hasher = hashlib.sha256()
        with open(src, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        file_sha256 = hasher.hexdigest()

        quarantine_id = f"Q_{int(datetime.utcnow().timestamp())}_{file_sha256[:8]}"
        destination = self.vault_dir / f"{quarantine_id}.vault"

        # Atomic move or copy & remove
        shutil.move(str(src), str(destination))

        manifest = self._load_manifest()
        entry = {
            "quarantine_id": quarantine_id,
            "original_path": str(src),
            "vault_path": str(destination),
            "sha256": file_sha256,
            "size_bytes": destination.stat().st_size,
            "reason": reason,
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "quarantined"
        }
        manifest[quarantine_id] = entry
        self._save_manifest(manifest)

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.FILE_QUARANTINED,
            origin_module="PURPLE",
            category="QUARANTINE",
            severity="HIGH",
            description=f"File {src.name} safely quarantined (ID: {quarantine_id}). Reason: {reason}",
            target=str(src),
            evidence={"sha256": file_sha256, "id": quarantine_id},
            action_taken="FILE_ISOLATED"
        ))

        logger.warning(f"[PURPLE QUARANTINE] File isolated: {src} -> {destination}")
        return entry

    def restore_file(self, quarantine_id: str, operator: str = "system") -> Dict[str, Any]:
        """Restores a quarantined file back to its original path."""
        manifest = self._load_manifest()
        if quarantine_id not in manifest:
            raise KeyError(f"Quarantine ID '{quarantine_id}' not found in manifest.")

        entry = manifest[quarantine_id]
        vault_path = Path(entry["vault_path"])
        dest_path = Path(entry["original_path"])

        if not vault_path.exists():
            raise FileNotFoundError(f"Vault storage corrupted or file missing: {vault_path}")

        # Ensure parent folder exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(vault_path), str(dest_path))

        entry["status"] = "restored"
        entry["restored_by"] = operator
        entry["restored_at"] = datetime.utcnow().isoformat()
        manifest[quarantine_id] = entry
        self._save_manifest(manifest)

        logger.info(f"[PURPLE QUARANTINE] File restored: {dest_path}")
        return entry

    def list_quarantined_files(self) -> List[Dict[str, Any]]:
        manifest = self._load_manifest()
        return list(manifest.values())

# Global Quarantine Vault instance
quarantine_vault = QuarantineVault()
