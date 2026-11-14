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
    # Wake up the engine if not already online
    engine_runtime.startup()
    print_banner()
    console.print("[bold cyan]Bienvenido a INDRA TERMINAL. Escribe [bold white]'help'[/bold white] para ver la matriz de comandos o [bold white]'exit'[/bold white] para salir.[/bold cyan]\n")

    completer = WordCompleter(COMMANDS_LIST, ignore_case=True)
    custom_style = Style.from_dict({
        "prompt": "#00f0ff bold",
    })

    session = PromptSession(completer=completer, style=custom_style)

    while True:
        try:
            prompt_text = [
                ("class:prompt", "indra-infinity > ")
            ]
            user_input = session.prompt(prompt_text).strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                console.print("[bold purple]Cerrando sesion de Indra Terminal. Infinity en guardia.[/bold purple]")
                break

            if user_input.lower() == "clear":
                console.clear()
                print_banner()
                continue

            # Strip leading 'indra' or 'gojo' if user typed it out
            if user_input.lower().startswith("indra "):
                user_input = user_input[6:].strip()
            elif user_input.lower().startswith("gojo "):
                user_input = user_input[5:].strip()

            GojoCommandHandler.execute(user_input)
            console.print()

        except KeyboardInterrupt:
            console.print("\n[yellow]KeyboardInterrupt received. Type 'exit' to quit.[/yellow]")
            continue
        except EOFError:
            break
        except Exception as e:
            console.print(f"[bold red][!] Unhandled exception: {e}[/bold red]")

if __name__ == "__main__":
    run_shell()
