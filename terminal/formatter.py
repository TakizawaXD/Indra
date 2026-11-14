"""
INDRA INFINITY SECURITY ∞ — TERMINAL FORMATTER & ART
Arquitecto y Creador: Takizawa | Para: Indra
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """[bold cyan]
 ██╗███╗   ██╗██████╗ ██████╗  █████╗ 
 ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗
 ██║██╔██╗ ██║██║  ██║██████╔╝███████║
 ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║
 ██║██║ ╚████║██████╔╝██║  ██║██║  ██║
 ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold cyan][bold blue]      INFINITY SECURITY ∞[/bold blue]
[bold purple]"NOTHING GETS THROUGH INFINITY."[/bold purple]
[dim cyan]CREADOR: Takizawa | EXCLUSIVO PARA: Indra[/dim cyan]
"""

def print_banner():
    console.print(BANNER)

def print_success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")

def print_info(msg: str):
    console.print(f"[bold cyan][*][/bold cyan] {msg}")

def print_warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")

def print_error(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")

def render_table(title: str, columns: list[str], rows: list[list[str]], style: str = "cyan"):
    table = Table(title=title, border_style=style, show_header=True, header_style=f"bold {style}")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)
