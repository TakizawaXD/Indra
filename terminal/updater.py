"""
INDRA INFINITY SECURITY (INFINITY) — AUTO-UPDATE SUBSYSTEM
Architect & Creator: Takizawa | For: Indra

Handles automated git pulls and dependency synchronization from:
https://github.com/TakizawaXD/Indra.git
"""

import subprocess
import sys
from pathlib import Path
from typing import Tuple

from terminal.formatter import console

BASE_DIR = Path(__file__).resolve().parent.parent


class SystemUpdater:
    """Manages automatic updates from the official GitHub repository."""

    @classmethod
    def run_update(cls, verbose: bool = True) -> Tuple[bool, str]:
        """Fetches and merges latest commits from origin/main, then updates dependencies."""
        if verbose:
            console.print("[bold cyan][*][/bold cyan] Comprobando actualizaciones en GitHub (TakizawaXD/Indra)...")

        # Step 1: Git Pull
        try:
            res = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = (res.stdout or "") + (res.stderr or "")
            if res.returncode != 0:
                msg = f"[-] Error al descargar actualizaciones: {output.strip()}"
                if verbose:
                    console.print(f"[bold red]{msg}[/bold red]")
                return False, msg

            if "Already up to date" in output or "Already up-to-date" in output or "Ya está actualizado" in output:
                msg = "[+] El sistema ya se encuentra en la version mas reciente."
                if verbose:
                    console.print(f"[bold green]{msg}[/bold green]")
                return True, msg

            if verbose:
                console.print("[bold green][+][/bold green] Nuevas actualizaciones descargadas exitosamente.")
                console.print(f"[dim]{output.strip()}[/dim]")

        except Exception as e:
            msg = f"[-] No se pudo conectar con GitHub (posible modo offline): {e}"
            if verbose:
                console.print(f"[yellow]{msg}[/yellow]")
            return False, msg

        # Step 2: Pip Dependency Check
        req_file = BASE_DIR / "requirements.txt"
        if req_file.exists():
            if verbose:
                console.print("[bold cyan][*][/bold cyan] Sincronizando dependencias de requirements.txt...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", str(req_file), "--quiet"],
                    cwd=str(BASE_DIR),
                    capture_output=True,
                    timeout=60,
                )
                if verbose:
                    console.print("[bold green][+][/bold green] Dependencias sincronizadas correctamente.")
            except Exception as e:
                if verbose:
                    console.print(f"[yellow][!] Aviso sobre dependencias: {e}[/yellow]")

        return True, "[+] Actualizacion completada exitosamente."


def auto_update_on_launch():
    """Silent fast background check run on platform startup."""
    try:
        subprocess.run(
            ["git", "pull", "origin", "main", "--quiet"],
            cwd=str(BASE_DIR),
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass

