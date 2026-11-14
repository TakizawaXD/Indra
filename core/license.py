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
    def validate_key_string(cls, candidate: str) -> bool:
        """Validates a key candidate string against the authorized SHA-256 hash."""
        if not candidate:
            return False
        cleaned = candidate.strip().strip('"').strip("'").strip()
        return hmac.compare_digest(hash_key(cleaned), AUTHORIZED_KEY_SHA256)

    @classmethod
    def save_key(cls, key: str) -> bool:
        """Persists a valid key to config/license.key."""
        try:
            cleaned = key.strip().strip('"').strip("'").strip()
            settings.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            key_path = settings.CONFIG_DIR / "license.key"
            key_path.write_text(cleaned, encoding="utf-8")
            return True
        except Exception as e:
            logger.error(f"Error al guardar la llave de licencia: {e}")
            return False

    @classmethod
    def prompt_interactive_license(cls) -> bool:
        """Prompts operator interactively in the terminal for the license key."""
        print("\n" + "=" * 60)
        print("INDRA INFINITY SECURITY (INFINITY) — ACTIVACION DE SISTEMA")
        print("Disenado Exclusivamente para: INDRA")
        print("Creador y Arquitecto del Sistema: TAKIZAWA")
        print("=" * 60)
        print("[*] El sistema requiere autenticacion de licencia para desbloquearse.")

        for attempt in range(1, 4):
            try:
                key_input = input("\n[?] Pega la llave de licencia de Indra como texto: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[-] Activacion cancelada por el operador.")
                return False

            if not key_input:
                continue

            if cls.validate_key_string(key_input):
                cls.save_key(key_input)
                print("[+] Llave autenticada exitosamente. Acceso concedido para Indra.")
                print("[+] Licencia registrada en config/license.key\n")
                return True
            else:
                print(f"[-] Llave no valida o no autorizada para Indra (Intento {attempt}/3).")

        print("[-] Limite de intentos superado. Acceso denegado.\n")
        return False

    @classmethod
    def enforce_license(cls, allow_prompt: bool = True) -> bool:
        """Halts initialization if the license key is invalid or absent."""
        if cls.verify_license():
            return True

        if allow_prompt and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            if cls.prompt_interactive_license():
                return True

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
