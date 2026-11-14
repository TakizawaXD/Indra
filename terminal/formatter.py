"""
INDRA INFINITY SECURITY ∞ — TERMINAL FORMATTER & ART
Arquitecto y Creador: Takizawa | Para: Indra
"""

import os
import shutil
import sys

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Windows consoles default to cp1252, which cannot encode the banner glyphs.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console()


def is_termux() -> bool:
    """Detects whether the application is running inside Android Termux."""
    return bool(
        os.environ.get("TERMUX_VERSION")
        or os.path.exists("/data/data/com.termux")
        or "com.termux" in os.environ.get("PREFIX", "")
    )


def get_terminal_width() -> int:
    """Dynamically returns terminal column width, handling mobile Termux resizes."""
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
        return max(cols, 36)
    except Exception:
        return console.size.width or 80


def is_compact_screen() -> bool:
    """Returns True if the current viewport is compact (mobile Termux or narrow terminal)."""
    return get_terminal_width() < 70 or (is_termux() and get_terminal_width() < 80)


BANNER_WIDE = """[bold cyan]
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

BANNER_COMPACT = """[bold cyan]INDRA INFINITY SECURITY ∞ [TERMUX][/bold cyan]
[bold purple]"NOTHING GETS THROUGH INFINITY."[/bold purple]
[dim cyan]Creador: Takizawa | Para: Indra[/dim cyan]"""

BANNER = BANNER_WIDE


def print_banner():
    width = get_terminal_width()
    if width < 55:
        console.print(Panel(BANNER_COMPACT, border_style="cyan", padding=(0, 1), expand=False))
    else:
        console.print(BANNER_WIDE)


def print_success(msg: str):
    console.print(f"[bold green][+][/bold green] {escape(str(msg))}")


def print_info(msg: str):
    console.print(f"[bold cyan][*][/bold cyan] {escape(str(msg))}")


def print_warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {escape(str(msg))}")


def print_error(msg: str):
    console.print(f"[bold red][-][/bold red] {escape(str(msg))}")


def render_table(title: str, columns: list[str], rows: list[list[str]], style: str = "cyan", markup: bool = False):
    """Renders a responsive table. Cell data is treated as plain text unless markup=True."""
    compact = is_compact_screen()
    table = Table(
        title=escape(title),
        border_style=style,
        show_header=True,
        header_style=f"bold {style}",
        padding=(0, 1) if compact else (0, 2),
        box=box.ROUNDED if compact else box.HEAVY_HEAD,
        expand=False,
    )
    for col in columns:
        table.add_column(col, overflow="fold" if compact else "ellipsis")
    for row in rows:
        cells = [str(c) if markup else Text("" if c is None else str(c)) for c in row]
        table.add_row(*cells)
    console.print(table)
