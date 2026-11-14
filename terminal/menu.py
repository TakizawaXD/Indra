"""
INDRA INFINITY SECURITY ∞ — NUMBERED MENU INTERFACE
Every operation of the platform is reachable by choosing numbers.
Options that need data (an IP, a URL, a password...) ask for it step by step.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from terminal.formatter import console

# (key, question, default) — default None means the value is required
Param = Tuple[str, str, Optional[str]]

TAG_STYLES = {
    "DEFENSA": "bold cyan",
    "ATAQUE": "bold red",
    "AMBAS": "bold magenta",
    "SISTEMA": "dim",
}


@dataclass
class MenuItem:
    label: str
    command: Optional[str] = None          # command template, e.g. "infinity ban {ip}"
    params: List[Param] = field(default_factory=list)
    submenu: Optional["Menu"] = None
    tag: str = ""


@dataclass
class Menu:
    title: str
    items: List[MenuItem]
    style: str = "cyan"


def _m(title: str, style: str, *items: MenuItem) -> Menu:
    return Menu(title=title, items=list(items), style=style)


MAIN_MENU = _m(
    "MENÚ PRINCIPAL — INDRA INFINITY ∞", "cyan",
    MenuItem("Panel de control", "dashboard", tag="AMBAS"),
    MenuItem("Monitor en vivo (Ctrl+C para volver)", "monitor", tag="AMBAS"),
    MenuItem("Infinity Shield — Defensa y bloqueo de IPs", tag="DEFENSA", submenu=_m(
        "INFINITY SHIELD", "cyan",
        MenuItem("Guia de uso de Infinity Shield", "guide infinity"),
        MenuItem("Estado del escudo y reglas activas", "infinity status"),
        MenuItem("Bloquear una IP (60 min)", "infinity ban {ip}", [("ip", "Dirección IP a bloquear", None)]),
        MenuItem("Desbloquear una IP", "infinity unban {ip}", [("ip", "Dirección IP a desbloquear", None)]),
    )),
    MenuItem("Blue — Reconocimiento", tag="ATAQUE", submenu=_m(
        "BLUE — RECONOCIMIENTO", "blue",
        MenuItem("Guia de uso de Blue Recon", "guide blue"),
        MenuItem("Escanear puertos comunes de un objetivo", "blue scan {target}",
                 [("target", "Objetivo autorizado", "127.0.0.1")]),
        MenuItem("Escanear puertos específicos", "blue scan {target} {ports}",
                 [("target", "Objetivo autorizado", "127.0.0.1"), ("ports", "Puertos separados por espacio (ej. 22 80 443)", None)]),
        MenuItem("Auditoría web (cabeceras, tecnologías, TLS)", "blue web {url}",
                 [("url", "URL autorizada (ej. http://127.0.0.1:8000)", None)]),
    )),
    MenuItem("Red — Auditoría controlada", tag="ATAQUE", submenu=_m(
        "RED — AUDITORÍA", "red",
        MenuItem("Guia de uso de Red Operations", "guide red"),
        MenuItem("Evaluar fortaleza de una contraseña", "red audit pass {password}",
                 [("password", "Contraseña a evaluar", None)]),
        MenuItem("Detectar métodos HTTP peligrosos", "red audit-methods {url}",
                 [("url", "URL autorizada", None)]),
    )),
    MenuItem("Purple — Riesgo, cuarentena e informes", tag="AMBAS", submenu=_m(
        "PURPLE — INTELIGENCIA", "magenta",
        MenuItem("Guia de uso de Purple Intel", "guide purple"),
        MenuItem("Índice de riesgo global", "purple risk"),
        MenuItem("Bóveda de cuarentena", "purple quarantine"),
        MenuItem("Generar informe ejecutivo", "report generate"),
        MenuItem("Ver informes generados", "report list"),
    )),
    MenuItem("Hollow Purple — Protocolo completo de 5 fases", "hollow-purple {target}",
             [("target", "Objetivo autorizado", "127.0.0.1")], tag="AMBAS"),
    MenuItem("Six Eyes — Asesor de seguridad", tag="AMBAS", submenu=_m(
        "SIX EYES", "cyan",
        MenuItem("Guia de uso de Six Eyes", "guide sixeyes"),
        MenuItem("Matriz de correlación", "sixeyes status"),
        MenuItem("Hacer una pregunta al asesor", "sixeyes ask {question}",
                 [("question", "Tu pregunta (ej. ¿qué es SQL injection?)", None)]),
    )),
    MenuItem("Redes — Diagnóstico y topología", tag="DEFENSA", submenu=_m(
        "REDES", "blue",
        MenuItem("Guia de uso de Redes", "guide network"),
        MenuItem("Diagnóstico de interfaces", "network diagnostics"),
        MenuItem("Topología de hosts y servicios", "network topology"),
        MenuItem("Calculadora de subred (CIDR)", "network subnet {cidr}", [("cidr", "Red CIDR (ej. 192.168.1.0/24)", None)]),
        MenuItem("Consulta DNS de un dominio", "network dns {domain}", [("domain", "Dominio", None)]),
    )),
    MenuItem("Inteligencia de IPs", tag="DEFENSA", submenu=_m(
        "INTELIGENCIA IP", "cyan",
        MenuItem("Guia de uso de Inteligencia IP", "guide ip"),
        MenuItem("Consultar una IP", "ip lookup {ip}", [("ip", "Dirección IP", None)]),
        MenuItem("Historial de visitas", "ip history"),
        MenuItem("Exportar historial a CSV", "ip export"),
    )),
    MenuItem("Vulnerabilidades y CVE", tag="AMBAS", submenu=_m(
        "VULNERABILIDADES", "yellow",
        MenuItem("Guia de uso de Vulnerabilidades", "guide vulnerability"),
        MenuItem("Vulnerabilidades catalogadas", "vulnerability"),
        MenuItem("Base CVE offline completa", "vulnerability cve"),
        MenuItem("Buscar CVE por componente", "vulnerability cve {component}",
                 [("component", "Componente (ej. log4j, runc, xz-utils)", None)]),
    )),
    MenuItem("Amenazas, incidentes y eventos", tag="AMBAS", submenu=_m(
        "REGISTRO DE SEGURIDAD", "red",
        MenuItem("Catálogo de amenazas", "threats"),
        MenuItem("Incidentes", "incidents"),
        MenuItem("Últimos eventos", "logs"),
    )),
    MenuItem("Laboratorio de práctica (seguro, en memoria)", tag="ATAQUE", submenu=_m(
        "LABORATORIO", "green",
        MenuItem("Guia de uso del Laboratorio", "guide lab"),
        MenuItem("Ver escenarios", "lab list"),
        MenuItem("Simular SQL Injection", "lab sqli {payload}", [("payload", "Payload", "' OR '1'='1")]),
        MenuItem("Simular XSS reflejado", "lab xss {payload}", [("payload", "Payload", "<script>alert(1)</script>")]),
        MenuItem("Simular login débil", "lab auth {user} {password}",
                 [("user", "Usuario", "operator"), ("password", "Contraseña", "password123")]),
    )),
    MenuItem("Servidor API (opcional)", tag="SISTEMA", submenu=_m(
        "SERVIDOR API", "cyan",
        MenuItem("Estado del servidor", "server status"),
        MenuItem("Iniciar servidor", "server start"),
        MenuItem("Iniciar en otro puerto", "server start {port}", [("port", "Puerto", None)]),
        MenuItem("Detener servidor", "server stop"),
    )),
    MenuItem("Actualizar sistema automaticamente (GitHub)", "update", tag="SISTEMA"),
    MenuItem("Manual de uso y guia de cada tecnica", "guide", tag="SISTEMA"),
    MenuItem("Sistema — Estado y configuración", tag="SISTEMA", submenu=_m(
        "SISTEMA", "white",
        MenuItem("Guia de auto-actualizacion", "guide update"),
        MenuItem("Telemetría y módulos", "status"),
        MenuItem("Configuración activa", "config"),
        MenuItem("Versión", "version"),
        MenuItem("Lista de comandos escritos (modo avanzado)", "help"),
    )),
)

LOCKED_MENU = _m(
    "SISTEMA BLOQUEADO — ACCESO RESTRINGIDO", "yellow",
    MenuItem("Insertar llave de licencia", "insertar llave"),
)


def render_menu(menu: Menu, is_root: bool) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("#", style=f"bold {menu.style}", justify="right")
    table.add_column("Opción")
    table.add_column("Tipo")
    for idx, item in enumerate(menu.items, start=1):
        label = Text(item.label)
        if item.submenu:
            label.append("  ›", style="dim")
        tag = Text(f"[{item.tag}]", style=TAG_STYLES.get(item.tag, "dim")) if item.tag else Text("")
        table.add_row(str(idx), label, tag)
    table.add_row("0", Text("Salir" if is_root else "Volver", style="dim"), Text(""))
    console.print(Panel(table, title=f"[bold {menu.style}]{menu.title}[/bold {menu.style}]", border_style=menu.style))
    console.print("[dim]Escribe el número de la opción (o un comando directo, p. ej. 'blue scan 127.0.0.1').[/dim]")


def build_command(item: MenuItem, ask: Callable[[str], str]) -> Optional[str]:
    """Asks for each parameter and returns the final command, or None if cancelled."""
    values = {}
    for key, question, default in item.params:
        suffix = f" [{default}]" if default else ""
        try:
            answer = ask(f"{question}{suffix}: ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if not answer:
            if default is None:
                console.print("[yellow][!] Valor obligatorio. Operación cancelada.[/yellow]")
                return None
            answer = default
        values[key] = answer
    return item.command.format(**values) if item.command else None
