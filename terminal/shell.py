"""
GOJO INFINITY SECURITY ∞ — INTERACTIVE TERMINAL SHELL
Single user interface of the platform (there is no web interface).
Run via: python -m terminal.shell   (or start.sh / start.bat)

Navigation:
  - Numbered menus: type the option number, "0" goes back / exits.
  - Advanced mode: any written command still works (e.g. "blue scan 127.0.0.1").
"""

import logging
import sys
from typing import List

from terminal.formatter import print_banner, console, is_compact_screen
from terminal.commands import GojoCommandHandler
from terminal.menu import MAIN_MENU, LOCKED_MENU, Menu, build_command, render_menu
from terminal.server_control import api_server
from core.engine import engine_runtime
from core.license import IndraLicenseGuard
from core.logger import set_console_level

# Command tree used for Tab autocompletion (command -> subcommands)
COMMAND_TREE = {
    "help": None, "menu": None, "status": None, "version": None, "dashboard": None, "monitor": None,
    "config": None, "clear": None, "exit": None, "quit": None,
    "server": {"start": None, "stop": None, "status": None},
    "infinity": {"status": None, "rules": None, "signatures": None, "ban": None, "unban": None},
    "blue": {"scan": None, "web": None},
    "red": {"audit": {"pass": None}, "audit-methods": None, "deep": None},
    "purple": {"risk": None, "quarantine": None, "report": None},
    "sixeyes": {"status": None, "ask": None},
    "hollow-purple": None,
    "network": {"diagnostics": None, "topology": None, "subnet": None, "dns": None},
    "ip": {"lookup": None, "history": None, "export": None},
    "vulnerability": {"list": None, "cve": None},
    "threats": None, "incidents": None, "logs": None,
    "lab": {"list": None, "sqli": None, "xss": None, "auth": None},
    "report": {"generate": None, "list": None},
}
COMMANDS_LIST = list(COMMAND_TREE)


class TerminalIO:
    """Reads user input with prompt_toolkit on a real console, or plain input() otherwise
    (piped input, IDE consoles, CI), so the terminal never crashes for lack of a TTY."""

    def __init__(self):
        self.session = None
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                from prompt_toolkit import PromptSession
                from prompt_toolkit.styles import Style
                self.session = PromptSession(style=Style.from_dict({"prompt": "#00f0ff bold"}))
            except Exception:
                self.session = None

    def set_commands(self, licensed: bool):
        if not self.session:
            return
        from prompt_toolkit.completion import NestedCompleter, WordCompleter
        if licensed:
            self.session.completer = NestedCompleter.from_nested_dict(COMMAND_TREE)
        else:
            self.session.completer = WordCompleter(["1", "0", "insertar llave", "exit", "quit", "clear"], ignore_case=True)

    def prompt(self, text: str) -> str:
        if self.session:
            from prompt_toolkit.patch_stdout import patch_stdout
            # patch_stdout keeps background output (API server) from corrupting the prompt line
            with patch_stdout(raw=True):
                return self.session.prompt([("class:prompt", text)])
        console.print(text, end="", style="bold cyan", markup=False, highlight=False)
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\r\n")

    def ask(self, text: str) -> str:
        """Secondary question (menu parameters, license key)."""
        if self.session:
            return self.session.prompt(text)
        console.print(text, end="", markup=False, highlight=False)
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\r\n")


def _try_unlock(candidate_key: str, io: TerminalIO) -> bool:
    if not IndraLicenseGuard.validate_key_string(candidate_key):
        console.print("[bold red][-][/bold red] Llave no valida o no autorizada para Indra.")
        console.print("[yellow][!] Elige 1 (Insertar llave) o pega directamente la clave correcta para reintentar.[/yellow]")
        return False
    IndraLicenseGuard.save_key(candidate_key)
    try:
        engine_runtime.startup()
    except Exception as e:
        console.print(f"[bold red][-][/bold red] Error al iniciar modulos: {e}")
    io.set_commands(True)
    console.print("[bold green][+][/bold green] Llave autenticada con exito. Bienvenido, Indra. Acceso concedido por Takizawa.")
    console.print("[bold cyan][*][/bold cyan] Todas las tecnicas (Blue, Red, Purple, Infinity, Six Eyes) han sido desbloqueadas.\n")
    return True


def _handle_locked_input(clean_cmd: str, io: TerminalIO) -> bool:
    """Processes input while locked. Returns True once the system is unlocked."""
    lower_cmd = clean_cmd.lower()
    candidate_key = ""

    if IndraLicenseGuard.validate_key_string(clean_cmd):
        candidate_key = clean_cmd
    elif lower_cmd in ("1", "insertar llave", "insertar-llave", "llave", "key"):
        try:
            candidate_key = io.ask("Pega la llave como texto > ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Operacion cancelada.[/yellow]")
            return False
    elif lower_cmd.startswith(("insertar llave ", "insertar-llave ")):
        candidate_key = clean_cmd[15:].strip()
    elif lower_cmd.startswith(("key ", "llave ")):
        candidate_key = clean_cmd.split(maxsplit=1)[1].strip()

    if candidate_key:
        return _try_unlock(candidate_key, io)

    console.print("[bold red][-][/bold red] SISTEMA BLOQUEADO. Elige [bold white]1[/bold white] para insertar la llave o [bold white]0[/bold white] para salir.")
    return False


def _shutdown():
    if api_server.is_running:
        api_server.stop()
    console.print("[bold purple]Cerrando sesion de Indra Terminal. Infinity en guardia.[/bold purple]")


def run_shell(io: TerminalIO = None):
    # Operational logs go to logs/gojo_infinity.log; on screen only errors, so the menu stays clean.
    set_console_level(logging.ERROR)
    io = io or TerminalIO()

    print_banner()
    is_licensed = IndraLicenseGuard.verify_license()
    if is_licensed:
        try:
            engine_runtime.startup()
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Error de inicio: {e}")
    else:
        console.print("[cyan]El sistema ha iniciado en modo protegido para uso exclusivo de INDRA.[/cyan]")
    io.set_commands(is_licensed)

    menu_stack: List[Menu] = [MAIN_MENU]
    show_menu = True

    while True:
        try:
            current = menu_stack[-1] if is_licensed else LOCKED_MENU
            if show_menu:
                render_menu(current, is_root=(not is_licensed or len(menu_stack) == 1))
            show_menu = True

            compact = is_compact_screen()
            if is_licensed:
                if compact:
                    crumb = menu_stack[-1].title.split(" — ")[0].title()[:12] if len(menu_stack) > 1 else ""
                    prompt_text = f"indra [{crumb}] > " if crumb else "indra > "
                else:
                    crumbs = " › ".join(m.title.split(" — ")[0].title() for m in menu_stack[1:])
                    prompt_text = f"indra-infinity [{crumbs}] > " if crumbs else "indra-infinity > "
            else:
                prompt_text = "indra [BLOQ] > " if compact else "indra-infinity [BLOQUEADO] > "

            user_input = io.prompt(prompt_text).strip()
            if not user_input:
                show_menu = False
                continue

            lowered = user_input.lower()
            if lowered in ("exit", "quit"):
                _shutdown()
                break
            if lowered == "clear":
                console.clear()
                print_banner()
                continue

            # Numbered navigation
            if user_input.isdigit():
                choice = int(user_input)
                if choice == 0:
                    if is_licensed and len(menu_stack) > 1:
                        menu_stack.pop()
                        continue
                    _shutdown()
                    break
                if not is_licensed:
                    is_licensed = _handle_locked_input(user_input, io)
                    continue
                if not 1 <= choice <= len(current.items):
                    console.print(f"[yellow][!] Opción {choice} no válida. Elige un número entre 0 y {len(current.items)}.[/yellow]")
                    show_menu = False
                    continue
                item = current.items[choice - 1]
                if item.submenu:
                    menu_stack.append(item.submenu)
                    continue
                command = build_command(item, io.ask)
                if command:
                    console.print()
                    GojoCommandHandler.execute(command)
                    console.print()
                continue

            # Written commands (advanced mode)
            clean_cmd = user_input
            if lowered.startswith("indra "):
                clean_cmd = clean_cmd[6:].strip()
            elif lowered.startswith("gojo "):
                clean_cmd = clean_cmd[5:].strip()

            if not is_licensed:
                is_licensed = _handle_locked_input(clean_cmd, io)
                continue

            if clean_cmd.lower() in ("menu", "menú", "inicio"):
                menu_stack = [MAIN_MENU]
                continue

            GojoCommandHandler.execute(clean_cmd)
            console.print()
            show_menu = False

        except KeyboardInterrupt:
            console.print("\n[yellow]Operación interrumpida. Escribe 0 o 'exit' para salir.[/yellow]")
        except EOFError:
            _shutdown()
            break
        except Exception as e:
            console.print(f"[!] Unhandled exception: {e}", style="bold red", markup=False)


if __name__ == "__main__":
    run_shell()
