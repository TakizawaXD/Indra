"""
INDRA INFINITY SECURITY ∞ — TERMINAL FORMATTER & ART
Arquitecto y Creador: Takizawa | Para: Indra
"""

import sys

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

# Windows consoles default to cp1252, which cannot encode the banner glyphs.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

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
    console.print(f"[bold green][+][/bold green] {escape(str(msg))}")

def print_info(msg: str):
    console.print(f"[bold cyan][*][/bold cyan] {escape(str(msg))}")

def print_warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {escape(str(msg))}")

def print_error(msg: str):
    console.print(f"[bold red][-][/bold red] {escape(str(msg))}")

def render_table(title: str, columns: list[str], rows: list[list[str]], style: str = "cyan", markup: bool = False):
    """Renders a table. Cell data is treated as plain text unless markup=True."""
    table = Table(title=escape(title), border_style=style, show_header=True, header_style=f"bold {style}")
    for col in columns:
        table.add_column(col)
    for row in rows:
        cells = [str(c) if markup else Text("" if c is None else str(c)) for c in row]
        table.add_row(*cells)
    console.print(table)
