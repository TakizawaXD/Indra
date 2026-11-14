"""
INDRA INFINITY SECURITY ∞ — LICENSE & ACCESS AUTHORIZATION GUARD
Restricts system access exclusively to Indra.
Architect & Creator: Takizawa

The plaintext key is never stored in source code: only its SHA-256 digest.
To rotate the key, run:  python -m core.license --hash "<NEW-KEY>"
and replace AUTHORIZED_KEY_SHA256 with the printed value.
"""

import hashlib
import hmac
import os
import sys

from core.config import settings
from core.logger import logger

AUTHORIZED_KEY_SHA256 = "f8a35a757c24e48cb01bf388a57bfedef9a82bbb76fb81f71c40c44b136e9919"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


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
                return key_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

        return ""

    @classmethod
    def verify_license(cls) -> bool:
        """Verifies license key authenticity (constant-time digest comparison)."""
        key = cls.get_current_key()
        if not key:
            return False
        return hmac.compare_digest(hash_key(key), AUTHORIZED_KEY_SHA256)

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


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--hash":
        print(hash_key(sys.argv[2]))
    else:
        print("Licencia valida." if IndraLicenseGuard.verify_license() else "Licencia NO valida.")
        sys.exit(0 if IndraLicenseGuard.verify_license() else 1)
