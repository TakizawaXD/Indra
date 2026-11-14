"""
INDRA INFINITY SECURITY (INFINITY) — OPERATIONAL GUIDES & MANUAL
Architect & Creator: Takizawa | For: Indra

Provides structured step-by-step documentation for every subsystem of the platform.
"""

from typing import Dict, List, Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from terminal.formatter import console, is_compact_screen, get_terminal_width

GUIDES: Dict[str, Dict] = {
    "infinity": {
        "title": "GUIA DE USO: INFINITY SHIELD (DEFENSA MULTICAPA)",
        "tag": "DEFENSA",
        "style": "cyan",
        "description": "Firewall de capa de aplicacion (WAF), control de acceso y mitigacion activa de ataques.",
        "concept": (
            "Infinity Shield filtra peticiones HTTP, previene ataques de fuerza bruta mediante "
            "rate limiting dinamico (240 peticiones/minuto por IP) y permite bloquear y desbloquear "
            "direcciones IP sospechosas de forma temporal o permanente."
        ),
        "steps": [
            ("1. Ver estado del escudo", "Escribe 'infinity status' para ver las reglas activas y lista de IPs bloqueadas."),
            ("2. Bloquear una IP sospechosa", "Escribe 'infinity ban 192.168.1.100' para aislar al atacante durante 60 minutos."),
            ("3. Desbloquear una IP", "Escribe 'infinity unban 192.168.1.100' para restaurar el acceso autorizado."),
            ("4. Ver reglas de seguridad", "Escribe 'infinity rules' para inspeccionar las politicas activas del WAF.")
        ],
        "example": "infinity ban 198.51.100.5"
    },
    "blue": {
        "title": "GUIA DE USO: BLUE RECON (RECONOCIMIENTO ACTIVO)",
        "tag": "ATAQUE",
        "style": "blue",
        "description": "Descubrimiento de la superficie de ataque, puertos abiertos y huellas de servicio en objetivos autorizados.",
        "concept": (
            "Utiliza sockets TCP asincronos sin requerir privilegios de superusuario (root). "
            "Identifica puertos estandares (SSH, HTTP, HTTPS, bases de datos), captura banners de servicio "
            "y audita cabeceras de seguridad HTTP, certificados TLS y tecnologias en servidores web."
        ),
        "steps": [
            ("1. Escaneo rapido de puertos comunes", "Escribe 'blue scan 127.0.0.1' para sondear los 16 puertos mas frecuentes."),
            ("2. Escaneo de puertos especificos", "Escribe 'blue scan 127.0.0.1 22 80 443 8000' para auditar puertos puntuales."),
            ("3. Auditoria web completa", "Escribe 'blue web http://127.0.0.1:8000' para inspeccionar cabeceras (HSTS, CSP, X-Frame) y TLS.")
        ],
        "example": "blue scan 127.0.0.1 80 443 8000"
    },
    "red": {
        "title": "GUIA DE USO: RED OPERATIONS (AUDITORIA OFENSIVA)",
        "tag": "ATAQUE",
        "style": "red",
        "description": "Evaluacion de fortaleza de contraseñas, configuraciones y metodos HTTP autorizados.",
        "concept": (
            "Verifica la robustez de controles de acceso. Evalua la entropia de Shannon de claves "
            "(detectando patrones debiles y longitud insuficiente) y sondea endpoints HTTP en busca de "
            "metodos inseguros permitidos por error (PUT, DELETE, TRACE)."
        ),
        "steps": [
            ("1. Auditar fortaleza de contraseña", "Escribe 'red audit pass ClaveSegura!2026' para calcular su entropia en bits."),
            ("2. Detectar metodos HTTP peligrosos", "Escribe 'red audit-methods http://127.0.0.1:8000' para verificar politicas de verbos HTTP.")
        ],
        "example": "red audit pass Indra#Infinity!2026"
    },
    "purple": {
        "title": "GUIA DE USO: PURPLE INTEL (CORRELACION Y CONTENCION)",
        "tag": "AMBAS",
        "style": "magenta",
        "description": "Sintesis de hallazgos ofensivos y defensivos, calculo de riesgo y reportes corporativos.",
        "concept": (
            "Purple une las tecnicas Blue y Red para cuantificar el riesgo global de la infraestructura "
            "en una escala de 0 a 100. Ademas, gestiona la boveda de cuarentena reversible y genera informes ejecutivos "
            "en formato Markdown y HTML imprimible con membrete corporativo de Indra."
        ),
        "steps": [
            ("1. Calcular indice de riesgo", "Escribe 'purple risk' para obtener la puntuacion y postura de seguridad actual."),
            ("2. Revisar boveda de cuarentena", "Escribe 'purple quarantine' para listar archivos sospechosos aislados."),
            ("3. Compilar informe ejecutivo", "Escribe 'report generate' para producir el informe en la carpeta reports/."),
            ("4. Listar informes historicos", "Escribe 'report list' para ver todos los reportes emitidos para Indra.")
        ],
        "example": "report generate"
    },
    "hollow-purple": {
        "title": "GUIA DE USO: HOLLOW PURPLE (PROTOCOLO DEFINITIVO)",
        "tag": "AMBAS",
        "style": "magenta",
        "description": "Convergencia automatizada de las tecnicas Blue, Red, Purple, Infinity y Six Eyes.",
        "concept": (
            "Hollow Purple es el procedimiento maestro de Indra Infinity. Ejecuta 5 fases secuenciales:\n"
            "  Fase 1 [Blue]: Escanea la superficie de ataque del objetivo autorizado.\n"
            "  Fase 2 [Red]: Evalua la exposicion de servicios y metodos.\n"
            "  Fase 3 [Purple]: Sintetiza los hallazgos y compila el informe.\n"
            "  Fase 4 [Infinity]: Aplica contencion preventiva y reglas de blindaje.\n"
            "  Fase 5 [Six Eyes]: Emite la calificacion global y plan de accion prioritario."
        ),
        "steps": [
            ("1. Ejecutar protocolo sobre un objetivo", "Escribe 'hollow-purple 127.0.0.1' y observa la convergencia visual en vivo.")
        ],
        "example": "hollow-purple 127.0.0.1"
    },
    "sixeyes": {
        "title": "GUIA DE USO: SIX EYES (CEREBRO ANALITICO)",
        "tag": "AMBAS",
        "style": "cyan",
        "description": "Correlacion cognitiva de eventos y asistente de ciberseguridad offline.",
        "concept": (
            "Six Eyes analiza en tiempo real el registro de eventos del sistema, detecta anomalias "
            "y correlaciona alertas. Incluye una base de conocimiento offline de ciberseguridad para responder "
            "dudas tecnicas sin depender de conexion a internet ni APIs externas."
        ),
        "steps": [
            ("1. Ver correlacion de amenazas", "Escribe 'sixeyes status' para analizar los eventos recientes."),
            ("2. Consultar al asistente", "Escribe 'sixeyes ask Que es Cross-Site Scripting?' para obtener explicacion y mitigacion.")
        ],
        "example": "sixeyes ask Como mitigar inyecciones SQL?"
    },
    "network": {
        "title": "GUIA DE USO: INTELIGENCIA DE REDES",
        "tag": "DEFENSA",
        "style": "blue",
        "description": "Diagnostico de interfaces, mapa de topologia, calculadora CIDR y resolucion DNS.",
        "concept": (
            "Proporciona visibilidad del entorno de red local y remoto. Identifica interfaces activas, "
            "calcula rangos de subred, mascaras y hosts utilizables, y consulta registros DNS (A, MX, NS, TXT)."
        ),
        "steps": [
            ("1. Diagnosticar interfaces locales", "Escribe 'network diagnostics' para ver IPs privadas, mascaras y gateways."),
            ("2. Ver topologia de red", "Escribe 'network topology' para mapear nodos y conexiones."),
            ("3. Calcular parametros de subred", "Escribe 'network subnet 192.168.1.0/24' para obtener primer y ultimo host util."),
            ("4. Consultar registros DNS", "Escribe 'network dns google.com' para auditar resolucion de nombres.")
        ],
        "example": "network subnet 10.0.0.0/24"
    },
    "ip": {
        "title": "GUIA DE USO: INTELIGENCIA DE DIRECCIONES IP",
        "tag": "DEFENSA",
        "style": "cyan",
        "description": "Lookup de reputacion, ASN, geolocalizacion aproximada y registro de visitas con consentimiento.",
        "concept": (
            "Permite auditar la reputacion publica de direcciones IP, organizacion y proveedor de red (ASN). "
            "Asimismo, gestiona el modulo de registro de visitas tecnicas informadas con politica de retencion a 30 dias."
        ),
        "steps": [
            ("1. Consultar una direccion IP", "Escribe 'ip lookup 8.8.8.8' para obtener pais aproximado, ASN y reputacion."),
            ("2. Ver historial de visitas registradas", "Escribe 'ip history' para listar accesos con consentimiento."),
            ("3. Exportar historial a archivo", "Escribe 'ip export' para generar un volcado en formato CSV.")
        ],
        "example": "ip lookup 1.1.1.1"
    },
    "vulnerability": {
        "title": "GUIA DE USO: CATALOGO CVE Y VULNERABILIDADES",
        "tag": "AMBAS",
        "style": "yellow",
        "description": "Base de datos offline de Common Vulnerabilities and Exposures y puntuacion CVSS v3.1.",
        "concept": (
            "Permite auditar software y librerias contra vulnerabilidades criticas conocidas "
            "(como Log4Shell, XZ Utils backdoor, Spring4Shell, OpenSSL RCE) sin requerir internet."
        ),
        "steps": [
            ("1. Listar vulnerabilidades del sistema", "Escribe 'vulnerability' para ver hallazgos detectados."),
            ("2. Consultar catalogo CVE offline", "Escribe 'vulnerability cve' para ver el catalogo completo."),
            ("3. Buscar CVE por componente", "Escribe 'vulnerability cve log4j' para filtrar vulnerabilidades especificas.")
        ],
        "example": "vulnerability cve openssl"
    },
    "lab": {
        "title": "GUIA DE USO: ATTACK LAB (LABORATORIO EN MEMORIA)",
        "tag": "ATAQUE",
        "style": "green",
        "description": "Entorno seguro de simulacion y entrenamiento de ataques en memoria sin persistencia.",
        "concept": (
            "Diseñado para validar la eficacia defensiva de Infinity Shield. Permite probar inyecciones SQL "
            "sinteticas, XSS reflejado y ataques a formularios de autenticacion de forma totalmente aislada."
        ),
        "steps": [
            ("1. Ver escenarios de practica", "Escribe 'lab list' para listar los 3 entornos disponibles."),
            ("2. Simular SQL Injection", "Escribe 'lab sqli \"admin\" --' para probar bypass de consulta SQL."),
            ("3. Simular XSS reflejado", "Escribe 'lab xss \"<script>alert(1)</script>\"' para verificar filtrado HTML."),
            ("4. Simular login con credenciales", "Escribe 'lab auth operator password123' para auditar respuestas.")
        ],
        "example": "lab sqli ' OR '1'='1"
    },
    "update": {
        "title": "GUIA DE USO: ACTUALIZACION AUTOMATICA DEL SISTEMA",
        "tag": "SISTEMA",
        "style": "green",
        "description": "Sincronizacion continua del repositorio oficial de Takizawa en GitHub.",
        "concept": (
            "El sistema cuenta con actualizacion automatica en dos niveles:\n"
            "  1. Inicio Automatico: 'start.bat' y 'start.sh' verifican y descargan actualizaciones silenciosamente antes de abrir la consola.\n"
            "  2. Comando Directo: Escribe 'update' o selecciona la opcion numerica en cualquier momento para forzar la actualizacion."
        ),
        "steps": [
            ("1. Actualizar desde la terminal", "Escribe 'update' para sincronizar con https://github.com/TakizawaXD/Indra."),
            ("2. Actualizar desde script Windows", "Ejecuta 'update.bat' para actualizar dependencias y codigo fuente."),
            ("3. Actualizar desde script Linux/Termux", "Ejecuta 'bash update.sh' para actualizar de forma asistida.")
        ],
        "example": "update"
    }
}


def print_module_guide(module_key: str):
    """Prints the comprehensive guide for a specific module, adapting responsively to screen size."""
    guide = GUIDES.get(module_key.lower())
    if not guide:
        console.print(f"[bold red][-][/bold red] No existe guia para el modulo: '{module_key}'.")
        console.print(f"[dim]Modulos disponibles: {', '.join(GUIDES.keys())}[/dim]")
        return

    compact = is_compact_screen()
    width = get_terminal_width()

    if compact:
        # Responsive stacked steps for mobile Termux
        body = Text()
        body.append(f"{guide['description']}\n\n", style="white")
        body.append("PASOS OPERATIVOS:\n", style=f"bold {guide['style']}")
        for step, desc in guide["steps"]:
            body.append(f"[*] {step}\n", style=f"bold {guide['style']}")
            body.append(f"    {desc}\n", style="dim")

        title_text = f"{guide['title'].replace('GUIA DE USO: ', '')} [{guide['tag'][:3]}]"
        panel = Panel(
            body,
            title=f"[bold {guide['style']}]{title_text}[/bold {guide['style']}]",
            subtitle=f"[dim]Ej: {guide['example']}[/dim]",
            border_style=guide["style"],
            padding=(0, 1),
            expand=False,
        )
        console.print(panel)
    else:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Paso", style=f"bold {guide['style']}", width=32)
        table.add_column("Instruccion", style="white")

        for step, desc in guide["steps"]:
            table.add_row(step, desc)

        panel = Panel(
            table,
            title=f"[bold {guide['style']}]{guide['title']}[/bold {guide['style']}] [{guide['tag']}]",
            subtitle=f"[dim]Ejemplo: {guide['example']}[/dim]",
            border_style=guide["style"]
        )
        console.print(panel)


def print_guide_index():
    """Prints the full index of all available guides, adaptively formatted."""
    compact = is_compact_screen()

    if compact:
        table = Table(
            title="INDRA INFINITY — GUIAS DISPONIBLES",
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("#", style="bold cyan", justify="right", width=3)
        table.add_column("Tecnica / Comando", style="bold white", overflow="fold")
        for idx, (k, g) in enumerate(GUIDES.items(), start=1):
            tag_color = "cyan" if g["tag"] == "DEFENSA" else "red" if g["tag"] == "ATAQUE" else "magenta" if g["tag"] == "AMBAS" else "white"
            row_label = f"{k.upper()} [{tag_color}][{g['tag'][:3]}][/{tag_color}]  -> guide {k}"
            table.add_row(str(idx), row_label)
        console.print(table)
        console.print("[dim]Escribe: [bold white]guide <modulo>[/bold white] (ej. 'guide blue').[/dim]")
    else:
        table = Table(title="INDRA INFINITY SECURITY (INFINITY) — MANUAL OPERATIVO & GUIAS", show_header=True, header_style="bold cyan", border_style="cyan")
        table.add_column("#", style="bold cyan", justify="right", width=4)
        table.add_column("Modulo / Tecnica", style="bold white", width=22)
        table.add_column("Tipo", width=12)
        table.add_column("Comando Directo", style="cyan", width=26)
        table.add_column("Descripcion", style="dim")

        for idx, (k, g) in enumerate(GUIDES.items(), start=1):
            tag_color = "cyan" if g["tag"] == "DEFENSA" else "red" if g["tag"] == "ATAQUE" else "magenta" if g["tag"] == "AMBAS" else "white"
            table.add_row(str(idx), k.upper(), f"[{tag_color}][{g['tag']}][/{tag_color}]", f"guide {k}", g["description"])

        console.print(table)
        console.print("[dim]Para consultar una guia especifica, escribe: [bold white]guide <modulo>[/bold white] (ej. 'guide blue' o 'guide hollow-purple').[/dim]")
