"""
INDRA INFINITY SECURITY ∞ — LICENSE & ACCESS AUTHORIZATION GUARD
Restricts system access exclusively to Indra.
Architect & Creator: Takizawa
"""

import os
from pathlib import Path
from core.config import settings
from core.logger import logger

AUTHORIZED_INDRA_KEY = "INDRA-TAKIZAWA-INFINITY-KEY-9F4E-8C2A-7B1D-2026"

class IndraLicenseGuard:
    """Verifies that the platform is licensed and authorized for Indra."""

    @classmethod
    def get_current_key(cls) -> str:
        # 1. Environment variable override
        env_key = os.getenv("INDRA_LICENSE_KEY")
        if env_key:
            return env_key.strip()

        # 2. File lookup in config/license.key
        key_path = settings.CONFIG_DIR / "license.key"
        if key_path.exists():
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                pass

        return ""

    @classmethod
    def verify_license(cls) -> bool:
        """Verifies license key authenticity."""
        key = cls.get_current_key()
        return key == AUTHORIZED_INDRA_KEY

    @classmethod
    def enforce_license(cls):
        """Halts initialization if the license key is invalid or absent."""
        if not cls.verify_license():
            msg = (
                "\n============================================================\n"
                "[-] ACCESO DENEGADO — LICENCIA NO VALIDA\n"
                "Este software fue desarrollado exclusivamente para INDRA.\n"
                "Creador y Arquitecto del Sistema: Takizawa\n\n"
                "Por favor, configure la llave valida en: config/license.key\n"
                "o defina la variable de entorno INDRA_LICENSE_KEY\n"
                "============================================================\n"
            )
            logger.critical(msg)
            raise PermissionError("Acceso bloqueado: Llave de licencia exclusiva para Indra requerida.")

