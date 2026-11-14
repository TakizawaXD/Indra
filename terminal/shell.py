"""
GOJO INFINITY SECURITY ∞ — INTERACTIVE TERMINAL SHELL
Entrypoint for the Gojo CLI in Android Termux.
Run via: python -m terminal.shell
"""

import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style

from terminal.formatter import print_banner, console
from terminal.commands import GojoCommandHandler
from core.engine import engine_runtime

COMMANDS_LIST = [
    "help", "status", "version", "dashboard", "exit", "quit", "clear",
    "infinity", "blue", "red", "purple", "sixeyes", "hollow-purple",
    "network", "ip", "vulnerability", "protect", "firewall",
    "threats", "incidents", "logs", "lab", "report"
]

def run_shell():
    print_banner()
    from core.license import IndraLicenseGuard
    is_licensed = IndraLicenseGuard.verify_license()

    if is_licensed:
        try:
            engine_runtime.startup()
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Error de inicio: {e}")
        console.print("[bold cyan]Bienvenido a INDRA TERMINAL. Escribe [bold white]'help'[/bold white] para ver la matriz de comandos o [bold white]'exit'[/bold white] para salir.[/bold cyan]\n")
        active_completer = WordCompleter(COMMANDS_LIST, ignore_case=True)
    else:
        console.print("[bold yellow][!] SISTEMA BLOQUEADO — ACCESO RESTRINGIDO[/bold yellow]")
        console.print("[cyan]El sistema ha iniciado en modo protegido para uso exclusivo de INDRA.[/cyan]")
        console.print("[bold green]Unica opcion disponible: [bold white]'insertar llave'[/bold white][/bold green]")
        console.print("[dim]Escribe 'insertar llave', pega la clave como texto y presiona Enter para acceder.[/dim]\n")
        active_completer = WordCompleter(["insertar llave", "exit", "quit", "clear"], ignore_case=True)

    custom_style = Style.from_dict({
        "prompt": "#00f0ff bold",
    })

    session = PromptSession(completer=active_completer, style=custom_style)

    while True:
        try:
            if is_licensed:
                prompt_text = [("class:prompt", "indra-infinity > ")]
            else:
                prompt_text = [("class:prompt", "indra-infinity [BLOQUEADO] > ")]

            user_input = session.prompt(prompt_text).strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                console.print("[bold purple]Cerrando sesion de Indra Terminal. Infinity en guardia.[/bold purple]")
                break

            if user_input.lower() == "clear":
                console.clear()
                print_banner()
                if not is_licensed:
                    console.print("[bold yellow][!] SISTEMA BLOQUEADO — UNICA OPCION: 'insertar llave'[/bold yellow]\n")
                continue

            # Strip leading 'indra' or 'gojo' if user typed it out
            clean_cmd = user_input
            if clean_cmd.lower().startswith("indra "):
                clean_cmd = clean_cmd[6:].strip()
            elif clean_cmd.lower().startswith("gojo "):
                clean_cmd = clean_cmd[5:].strip()

            # Handle locked state
            if not is_licensed:
                lower_cmd = clean_cmd.lower()
                if lower_cmd == "insertar llave" or lower_cmd == "insertar-llave" or lower_cmd.startswith("insertar llave ") or lower_cmd.startswith("key "):
                    # Extract inline key if provided
                    candidate_key = ""
                    if lower_cmd.startswith("insertar llave "):
                        candidate_key = clean_cmd[15:].strip()
                    elif lower_cmd.startswith("key "):
                        candidate_key = clean_cmd[4:].strip()

                    # If not inline, prompt for it
                    if not candidate_key:
                        try:
                            candidate_key = session.prompt("Pega la llave como texto > ").strip()
                        except (KeyboardInterrupt, EOFError):
                            console.print("\n[yellow]Operacion cancelada.[/yellow]")
                            continue

                    if IndraLicenseGuard.validate_key_string(candidate_key):
                        IndraLicenseGuard.save_key(candidate_key)
                        is_licensed = True
                        try:
                            engine_runtime.startup()
                        except Exception as e:
                            console.print(f"[bold red][-][/bold red] Error al iniciar modulos: {e}")
                        console.print("[bold green][+][/bold green] Llave autenticada con exito. Bienvenido, Indra. Acceso concedido por Takizawa.")
                        console.print("[bold cyan][*][/bold cyan] Todas las tecnicas (Blue, Red, Purple, Infinity, Six Eyes) han sido desbloqueadas.")
                        console.print("[dim]Escribe 'help' para explorar los comandos operativos.[/dim]\n")
                        session.completer = WordCompleter(COMMANDS_LIST, ignore_case=True)
                    else:
                        console.print("[bold red][-][/bold red] Llave no valida o no autorizada para Indra.")
                        console.print("[yellow][!] Usa 'insertar llave' para reintentar.[/yellow]")
                else:
                    console.print("[bold red][-][/bold red] SISTEMA BLOQUEADO. La unica opcion disponible es: [bold white]'insertar llave'[/bold white]")
                    console.print("[dim]Escribe 'insertar llave' y pega la clave como texto para acceder.[/dim]")
                continue

            # Normal command execution when licensed
            GojoCommandHandler.execute(clean_cmd)
            console.print()

        except KeyboardInterrupt:
            console.print("\n[yellow]KeyboardInterrupt received. Type 'exit' to quit.[/yellow]")
            continue
        except EOFError:
            break
        except Exception as e:
            console.print(f"[!] Unhandled exception: {e}", style="bold red", markup=False)

if __name__ == "__main__":
    run_shell()
