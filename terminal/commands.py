"""
GOJO INFINITY SECURITY ∞ — TERMINAL COMMAND HANDLER
Dispatches all CLI commands to underlying modules with Rich formatting.
"""

import asyncio
import time
from typing import List

from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from core.config import settings
from terminal.formatter import console, print_banner, print_success, print_info, print_warning, print_error, render_table
from core.engine import engine_runtime
from core.orchestrator import six_eyes
from techniques.infinity.shield import infinity_shield
from techniques.blue.recon import blue_recon
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from techniques.purple.quarantine import quarantine_vault
from techniques.hollow_purple.protocol import HollowPurpleProtocol
from network.diagnostics import NetworkDiagnostics
from network.mapper import NetworkMapper
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer
from network.ports import TOP_PORTS
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from laboratory.web_lab import AttackLabSimulator
from laboratory.scenarios import LAB_SCENARIOS
from vulnerability.cve import CVEIntelligence, OFFLINE_CVE_FEED
from backend.database import SessionLocal, SecurityEvent, Vulnerability, Threat, Incident, SecurityReport
from terminal.server_control import api_server

SEVERITY_STYLES = {
    "CRITICAL": "bold magenta",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}


class GojoCommandHandler:
    """Dispatches Gojo terminal commands to functional subsystems."""

    @classmethod
    def execute(cls, cmd_line: str):
        parts = cmd_line.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        handlers = {
            "help": lambda: cls.cmd_help(args),
            "status": cls.cmd_status,
            "version": lambda: console.print(
                f"[bold cyan]Indra Infinity Security ∞[/bold cyan] v{settings.APP_VERSION} (Para: Indra | Creador: Takizawa)"
            ),
            "dashboard": cls.cmd_dashboard,
            "monitor": lambda: cls.cmd_monitor(args),
            "server": lambda: cls.cmd_server(args),
            "config": cls.cmd_config,
            "guide": lambda: cls.cmd_guide(args),
            "guia": lambda: cls.cmd_guide(args),
            "update": lambda: cls.cmd_update(args),
            "actualizar": lambda: cls.cmd_update(args),
            "infinity": lambda: cls.cmd_infinity(args),
            "protect": lambda: cls.cmd_infinity(args),
            "firewall": lambda: cls.cmd_infinity(args),
            "blue": lambda: cls.cmd_blue(args),
            "red": lambda: cls.cmd_red(args),
            "purple": lambda: cls.cmd_purple(args),
            "sixeyes": lambda: cls.cmd_sixeyes(args),
            "hollow-purple": lambda: cls.cmd_hollow_purple(args),
            "hollow_purple": lambda: cls.cmd_hollow_purple(args),
            "network": lambda: cls.cmd_network(args),
            "ip": lambda: cls.cmd_ip(args),
            "audit": lambda: cls.cmd_report(args),
            "vulnerability": lambda: cls.cmd_vulnerability(args),
            "threats": cls.cmd_threats,
            "incidents": cls.cmd_incidents,
            "logs": lambda: cls.cmd_logs(args),
            "lab": lambda: cls.cmd_lab(args),
            "report": lambda: cls.cmd_report(args),
        }

        handler = handlers.get(cmd)
        if handler is None:
            print_warning(f"Unknown command: '{cmd}'. Type 'help' for available commands.")
            return
        handler()

    @classmethod
    def cmd_help(cls, args: List[str]):
        print_banner()
        console.print("[bold cyan][DEFENSA][/bold cyan]: Proteger y bloquear | [bold red][ATAQUE][/bold red]: Auditar y evaluar | [bold purple][AMBAS][/bold purple]: Correlación y convergencia\n")
        table_rows = [
            ["dashboard", "[bold purple][AMBAS][/bold purple]", "Panel de control: métricas, riesgo y últimos eventos"],
            ["monitor [segundos]", "[bold purple][AMBAS][/bold purple]", "Panel en vivo con refresco automático (Ctrl+C para salir)"],
            ["status", "[bold purple][AMBAS][/bold purple]", "Telemetría en tiempo real de CPU, memoria y módulos activos"],
            ["infinity [status|rules|ban <ip>|unban <ip>]", "[bold cyan][DEFENSA][/bold cyan]", "Firewall WAF multicapa, rate limiter y bloqueo de IPs"],
            ["blue scan <target> [ports...]", "[bold red][ATAQUE][/bold red]", "Reconocimiento y escaneo TCP de puertos y servicios"],
            ["blue web <url>", "[bold red][ATAQUE][/bold red]", "Auditoría web no intrusiva: cabeceras, tecnologías y TLS"],
            ["red [audit pass <clave>|audit-methods <url>]", "[bold red][ATAQUE][/bold red]", "Auditoría de fortaleza de claves y métodos HTTP"],
            ["purple [risk|quarantine|report]", "[bold purple][AMBAS][/bold purple]", "Cálculo de riesgo (0-100), bóveda de cuarentena e informes"],
            ["sixeyes [status|ask <pregunta>]", "[bold purple][AMBAS][/bold purple]", "Asesor cognitivo offline de ciberseguridad"],
            ["hollow-purple <target>", "[bold purple][AMBAS][/bold purple]", "Protocolo definitivo de convergencia en 5 fases"],
            ["network [diagnostics|topology|subnet <cidr>|dns <dominio>]", "[bold cyan][DEFENSA][/bold cyan]", "Diagnóstico de interfaces de red locales y subredes"],
            ["ip [lookup <ip>|history|export]", "[bold cyan][DEFENSA][/bold cyan]", "Consulta de reputación de IPs y visitas informadas"],
            ["vulnerability [list|cve <componente>]", "[bold purple][AMBAS][/bold purple]", "Catálogo de vulnerabilidades y base CVE offline"],
            ["threats | incidents | logs", "[bold purple][AMBAS][/bold purple]", "Amenazas, incidentes y flujo de eventos recientes"],
            ["lab [list|sqli <p>|xss <p>|auth <u> <clave>]", "[bold red][ATAQUE][/bold red]", "Laboratorio seguro de práctica en memoria (SQLi/XSS)"],
            ["report [generate|list]", "[bold purple][AMBAS][/bold purple]", "Compilación de informes ejecutivos en Markdown y HTML"],
            ["server [start [puerto]|stop|status]", "[dim]SISTEMA[/dim]", "API REST opcional protegida por Infinity Shield"],
            ["config", "[dim]SISTEMA[/dim]", "Configuración activa del entorno y rutas de datos"],
            ["clear | exit / quit", "[dim]SISTEMA[/dim]", "Limpiar pantalla / salir de Indra Terminal"]
        ]
        table_rows = [[escape(cmd), purpose, escape(desc)] for cmd, purpose, desc in table_rows]
        render_table("MATRIZ DE COMANDOS INDRA INFINITY", ["Comando", "Propósito", "Descripción Operativa"], table_rows, style="cyan", markup=True)

    @classmethod
    def cmd_status(cls):
        telem = engine_runtime.get_telemetry()
        rows = [
            ["Engine Status", telem["status"]],
            ["Uptime (sec)", str(telem["uptime_seconds"])],
            ["Memory Usage", f"{telem['memory_usage_mb']} MB"],
            ["CPU Activity", f"{telem['cpu_percent']}%"]
        ]
        for mod, st in telem["modules"].items():
            rows.append([f"Module: {mod}", st])
        render_table("SIX EYES SYSTEM TELEMETRY", ["Metric", "Value"], rows, style="blue")

    @classmethod
    def cmd_infinity(cls, args: List[str]):
        sub = args[0].lower() if args else "status"
        if sub == "status":
            stats = infinity_shield.get_stats()
            rows = [[k.replace("_", " ").title(), str(v)] for k, v in stats.items()]
            render_table("INFINITY SHIELD STATUS", ["Metric", "Value"], rows, style="cyan")
            cls.cmd_infinity(["rules"])
        elif sub == "rules":
            rules = infinity_shield.get_active_rules()
            if not rules:
                print_info("No active IP ban rules. Infinity Shield is monitoring in real-time.")
                return
            rows = [[str(r["id"]), r["name"], r["type"], r["target"], str(r["hits"]), r["expires_at"]] for r in rules]
            render_table("INFINITY SHIELD ACTIVE RULES", ["ID", "Name", "Type", "Target", "Hits", "Expires"], rows, style="cyan")
        elif sub == "ban" and len(args) > 1:
            ip = args[1]
            try:
                infinity_shield.ban_ip(ip, reason="Manual operator ban from Indra Terminal", duration_minutes=60)
                print_success(f"IP {ip} banned for 60 minutes.")
            except ValueError as e:
                print_error(str(e))
        elif sub == "unban" and len(args) > 1:
            ip = args[1]
            if infinity_shield.unban_ip(ip):
                print_success(f"IP {ip} unbanned.")
            else:
                print_warning(f"No active ban found for {ip}.")
        else:
            print_warning("Usage: infinity [status|rules|ban <ip>|unban <ip>]")

    @classmethod
    def cmd_blue(cls, args: List[str]):
        if args and args[0].lower() == "web":
            cls.cmd_blue_web(args[1:])
            return
        rest = args[1:] if args and args[0].lower() == "scan" else args
        if not rest:
            print_warning("Usage: blue scan <target> [ports...|top]")
            return
        target = rest[0]
        extra = rest[1:]
        deep = False
        if extra and extra[0].lower() in ("top", "deep", "full"):
            ports = list(TOP_PORTS)
            deep = True
            extra = extra[1:]
        else:
            try:
                ports = sorted({int(p) for p in extra}) or None
            except ValueError:
                ports = [-1]
        if ports and any(p < 1 or p > 65535 for p in ports):
            print_error("Ports must be integers between 1 and 65535.")
            return

        scope = f"{len(ports)} puertos (barrido profundo)" if deep else (f"{len(ports)} puertos" if ports else "puertos comunes")
        print_info(f"Initiating Blue Reconnaissance on: {target} [{scope}]...")
        try:
            results = asyncio.run(blue_recon.scan_target_ports_and_save(target, ports=ports))
        except Exception as e:
            print_error(f"Blue scan error: {e}")
            return
        if not results:
            print_info("No open TCP ports detected on this target.")
            return
        rows = []
        risky = 0
        for r in results:
            is_risky = r.get("risk") == "HIGH"
            risky += 1 if is_risky else 0
            flag = "[bold red]ALTO[/bold red]" if is_risky else "info"
            rows.append([str(r["port"]), r["service"], r.get("version") or "-", flag, r["banner"] or ""])
        render_table(f"BLUE RECON: {target}", ["Port", "Service", "Version", "Riesgo", "Banner"], rows, style="blue", markup=True)
        if risky:
            print_warning(f"{risky} puerto(s) de alto riesgo expuestos. Revisa exposición en red y considera 'infinity ban' / cierre.")

    @classmethod
    def cmd_red(cls, args: List[str]):
        sub = args[0].lower() if args else "help"
        password = None
        if sub == "audit-auth" and len(args) > 1:
            password = " ".join(args[1:])
        elif sub == "audit" and len(args) > 2 and args[1].lower() in ("pass", "password"):
            password = " ".join(args[2:])

        if password is not None:
            res = red_operations.audit_password_strength(password)
            rows = [
                ["Length", str(res["length"])],
                ["Entropy", f"{res['entropy_bits']} bits"],
                ["Strength Tier", res["strength"]],
                ["Admin Grade", "YES" if res["is_acceptable_for_admin"] else "NO (Insufficient)"]
            ]
            render_table("PASSWORD STRENGTH AUDIT", ["Metric", "Assessment"], rows, style="red")
        elif sub == "audit-methods" and len(args) > 1:
            url = args[1]
            try:
                res = asyncio.run(red_operations.audit_http_methods(url))
            except Exception as e:
                print_error(f"HTTP methods audit error: {e}")
                return
            print_info(f"Allowed Methods: {res.get('allowed_methods')}")
            if res.get("insecure_methods_exposed"):
                print_warning(f"Dangerous Methods Exposed: {res['insecure_methods_exposed']}")
            else:
                print_success("No dangerous HTTP methods exposed.")
        elif sub == "deep" and len(args) > 1:
            cls.cmd_red_deep(args[1], args[2] if len(args) > 2 else None)
        else:
            print_warning("Usage: red audit pass <password> | red audit-methods <url> | red deep <url> [parametro]")

    @classmethod
    def cmd_red_deep(cls, url: str, param: str = None):
        print_info(f"Auditoría ofensiva profunda (no destructiva) sobre: {url}...")
        if param:
            print_info(f"Probando el parámetro '{param}' con sondas SQLi booleanas y canario XSS.")
        try:
            res = asyncio.run(red_operations.deep_web_audit(url, param_name=param))
        except Exception as e:
            print_error(f"Deep audit error: {e}")
            return

        level = res.get("risk_level", "LOW")
        style = "red" if level in ("HIGH", "CRITICAL") else "yellow" if level == "MEDIUM" else "green"
        headers = res.get("security_headers", {})
        paths = res.get("sensitive_paths", {})
        rows = [
            ["Riesgo global", f"[bold {style}]{res.get('risk_score', 0)}/100 ({level})[/bold {style}]"],
            ["Cabeceras ausentes", ", ".join(headers.get("missing_headers", [])) or "ninguna"],
            ["Debilidades", ", ".join(headers.get("weaknesses", [])) or "ninguna"],
            ["Métodos HTTP peligrosos", ", ".join(res.get("http_methods", {}).get("insecure_methods_exposed", [])) or "ninguno"],
            ["Archivos sensibles expuestos", ", ".join(e["path"] for e in paths.get("exposed", []) if e["path"] != "/robots.txt") or "ninguno"],
        ]
        if "sqli" in res:
            rows.append(["Indicio de SQLi", "SÍ" if res["sqli"].get("indication_of_sqli") else "no"])
        if "reflected_xss" in res:
            rows.append(["XSS reflejado", "SÍ" if res["reflected_xss"].get("reflected_unencoded") else "no"])
        render_table(f"RED DEEP AUDIT: {url}", ["Hallazgo", "Resultado"], rows, style=style, markup=True)
        print_info("Todos los hallazgos quedaron catalogados. Revisa 'purple risk' y 'report generate'.")

    @classmethod
    def cmd_purple(cls, args: List[str]):
        sub = args[0].lower() if args else "risk"
        if sub == "risk":
            risk = purple_intel.calculate_risk_index()
            rows = [
                ["Risk Index", f"{risk['risk_index']}/100"],
                ["Risk Level", risk["risk_level"]],
                ["Cataloged Vulnerabilities", str(risk["total_vulnerabilities"])],
                ["Active Threats", str(risk["active_threats"])],
                ["Open Ports Cataloged", str(risk["open_ports_cataloged"])]
            ]
            render_table("PURPLE INTELLIGENCE RISK POSTURE", ["Factor", "Metric"], rows, style="purple")
        elif sub == "quarantine":
            items = quarantine_vault.list_quarantined_files()
            if not items:
                print_info("Quarantine vault is empty.")
                return
            rows = [[i["quarantine_id"], i["original_path"], str(i["size_bytes"]), i["status"]] for i in items]
            render_table("PURPLE QUARANTINE VAULT", ["ID", "Original Path", "Bytes", "Status"], rows, style="purple")
        elif sub == "report":
            cls.cmd_report(["generate"])
        else:
            print_warning("Usage: purple [risk|quarantine|report]")

    @classmethod
    def cmd_sixeyes(cls, args: List[str]):
        if args and args[0].lower() == "ask":
            query = " ".join(args[1:]).strip()
            if not query:
                print_warning("Usage: sixeyes ask <pregunta>")
                return
            res = six_eyes.ai.ask(query)
            console.print(Panel(escape(res["answer"]), title="[bold cyan]SIX EYES ADVISOR[/bold cyan]", border_style="cyan"))
        else:
            corr = six_eyes.analyze_event_correlation()
            rows = [[k.replace("_", " ").title(), str(v)] for k, v in corr.items()]
            render_table("SIX EYES CORRELATION MATRIX", ["Metric", "State"], rows, style="cyan")

    @classmethod
    def cmd_hollow_purple(cls, args: List[str]):
        target = args[0] if args else "127.0.0.1"
        console.print("[bold purple]═══════════════════════════════════════════════════════════[/bold purple]")
        console.print("[bold cyan]BLUE (Recon)[/bold cyan] + [bold red]RED (Validation)[/bold red] -> [bold purple]HOLLOW PURPLE (虚式「茈」)[/bold purple]")
        console.print("[bold purple]═══════════════════════════════════════════════════════════[/bold purple]")
        try:
            res = asyncio.run(HollowPurpleProtocol.execute(target))
            print_success(f"Hollow Purple convergence complete on target: {target}")
            print_info(f"Posture Assessment: {res['phases']['six_eyes_synthesis']['posture_assessment']}")
        except Exception as e:
            print_error(f"Hollow Purple execution failed: {e}")

    @classmethod
    def cmd_network(cls, args: List[str]):
        sub = args[0].lower() if args else "diagnostics"
        if sub == "diagnostics":
            overview = NetworkDiagnostics.get_device_ip_overview()
            print_info(f"Primary Local IP: {overview.get('primary_local_ip')}")
            for iface in overview.get("interfaces", []):
                ips = [a["address"] for a in iface.get("ipv4", [])]
                if ips:
                    print_info(f"Interface {iface['interface']} (Up={iface['is_up']}): {', '.join(ips)}")
        elif sub == "topology":
            cls.cmd_network_topology()
        elif sub == "subnet" and len(args) > 1:
            res = SubnetCalculator.calculate_cidr(args[1])
            if "error" in res:
                print_error(res["error"])
            else:
                rows = [[k.replace("_", " ").title(), str(v)] for k, v in res.items()]
                render_table(f"SUBNET METRICS: {args[1]}", ["Property", "Value"], rows, style="blue")
        elif sub == "dns" and len(args) > 1:
            res = DNSAnalyzer.resolve_domain(args[1])
            rows = [[k, ", ".join(v) if v else "None"] for k, v in res["records"].items()]
            render_table(f"DNS RECORDS: {args[1]}", ["Record Type", "Resolved Values"], rows, style="blue")
        else:
            print_warning("Usage: network [diagnostics|subnet <cidr>|dns <dominio>]")

    @classmethod
    def cmd_ip(cls, args: List[str]):
        sub = args[0].lower() if args else "history"
        if sub == "lookup" and len(args) > 1:
            ip = args[1]
            res = asyncio.run(IPLookupEngine.lookup_ip(ip))
            if "error" in res:
                print_error(res["error"])
                return
            geo = res.get("geolocation", {})
            net = res.get("network", {})
            rows = [
                ["Target IP", res["ip"]],
                ["IP Version", f"IPv{res['version']}"],
                ["Private Range", "YES" if res["is_private"] else "NO (Public)"],
                ["Reverse DNS", res.get("reverse_dns") or "None"],
                ["Country (Approx)", str(geo.get("country"))],
                ["City (Approx)", str(geo.get("city"))],
                ["ASN", str(net.get("asn"))],
                ["Organization", str(net.get("organization"))]
            ]
            render_table(f"IP LOOKUP: {ip}", ["Property", "Heuristic Value"], rows, style="cyan")
            console.print(f"[dim yellow]* {geo.get('disclaimer')} [/dim yellow]")
        elif sub == "history":
            history = IPLoggerService.get_visit_history(limit=15)
            if not history:
                print_info("No visit history logged yet.")
                return
            rows = [[h["ip"], h["path"] or "", h["consent"], h["timestamp"]] for h in history]
            render_table("IP LOGGER INFORMED VISITS", ["IP Address", "Endpoint", "Consent", "Timestamp"], rows, style="cyan")
        elif sub == "export":
            out_file = settings.REPORTS_DIR / "ip_visits_export.csv"
            out_file.write_text(IPLoggerService.export_csv(), encoding="utf-8")
            print_success(f"CSV exported: {out_file}")
        else:
            print_warning("Usage: ip [lookup <ip>|history|export]")

    @classmethod
    def cmd_lab(cls, args: List[str]):
        sub = args[0].lower() if args else "list"
        if sub == "list":
            rows = [[s["id"], s["title"], s["category"], s["difficulty"]] for s in LAB_SCENARIOS.values()]
            render_table("SAFE ATTACK LAB SCENARIOS", ["Scenario ID", "Title", "Category", "Difficulty"], rows, style="green")
        elif sub == "sqli" and len(args) > 1:
            payload = " ".join(args[1:])
            res = AttackLabSimulator.test_sqli_endpoint(payload)
            AttackLabSimulator.record_lab_run("sqli_lab", 1, res)
            console.print(f"[*] Simulated Query: {res['simulated_query']}", markup=False, highlight=False)
            print_warning(f"Detection Status: {res['status'].upper()}")
            print_info(f"Rows Returned: {len(res['records_returned'])}")
        elif sub == "xss" and len(args) > 1:
            payload = " ".join(args[1:])
            res = AttackLabSimulator.test_xss_endpoint(payload)
            AttackLabSimulator.record_lab_run("xss_lab", 1, res)
            print_warning(f"Detection Status: {res['status'].upper()}")
            console.print(f"[*] Reflected: {res['reflected_html']}", markup=False, highlight=False)
        elif sub == "auth" and len(args) > 2:
            res = AttackLabSimulator.test_auth_endpoint(args[1], " ".join(args[2:]))
            AttackLabSimulator.record_lab_run("auth_lab", 1, res)
            if res["authenticated"]:
                print_warning(f"Authenticated as '{res['user']}': {res['warning']}")
            else:
                print_info("Authentication rejected (invalid credentials).")
        else:
            print_warning("Usage: lab [list|sqli <payload>|xss <payload>|auth <user> <password>]")

    @classmethod
    def cmd_threats(cls):
        with SessionLocal() as db:
            threats = db.query(Threat).order_by(Threat.detected_at.desc()).limit(20).all()
            if not threats:
                print_success("Zero active threats detected.")
                return
            rows = [[str(t.id), t.threat_type, t.source_ip or "N/A", t.severity, t.status, t.mitigation_applied or ""] for t in threats]
        render_table("THREAT CATALOG", ["ID", "Type", "Source IP", "Severity", "Status", "Mitigation"], rows, style="red")

    @classmethod
    def cmd_incidents(cls):
        with SessionLocal() as db:
            incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(20).all()
            if not incidents:
                print_success("Zero open security incidents.")
                return
            rows = [[str(i.id), i.title, i.severity, i.status, i.containment_action or ""] for i in incidents]
        render_table("INCIDENT MANAGER", ["ID", "Title", "Severity", "Status", "Containment"], rows, style="purple")

    @classmethod
    def cmd_logs(cls, args: List[str]):
        with SessionLocal() as db:
            events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(15).all()
            if not events:
                print_info("No security events logged.")
                return
            rows = [[e.origin_module, e.event_type, e.severity, e.description[:60], e.created_at.strftime("%H:%M:%S")] for e in events]
        render_table("TELEMETRY EVENT STREAM", ["Origin", "Type", "Severity", "Description", "Time"], rows, style="cyan")

    @classmethod
    def cmd_vulnerability(cls, args: List[str]):
        if args and args[0].lower() == "cve":
            query = " ".join(args[1:]).strip()
            items = CVEIntelligence.match_component(query) if query else OFFLINE_CVE_FEED
            if not items:
                print_info(f"No offline CVE entries match '{query}'.")
                return
            rows = [[i["cve_id"], i["affected_component"], str(i["cvss"]), i["mitigation"]] for i in items]
            render_table("OFFLINE CVE FEED", ["CVE", "Component", "CVSS", "Mitigation"], rows, style="yellow")
            return

        with SessionLocal() as db:
            vulns = db.query(Vulnerability).all()
            if not vulns:
                print_success("Zero vulnerabilities cataloged.")
                return
            rows = [[str(v.id), v.title[:35], v.severity, str(v.cvss_score), v.status, v.target[:25]] for v in vulns]
        render_table("VULNERABILITY CENTER", ["ID", "Title", "Severity", "CVSS", "Status", "Target"], rows, style="yellow")

    @classmethod
    def cmd_report(cls, args: List[str]):
        sub = args[0].lower() if args else "generate"
        if sub == "list":
            with SessionLocal() as db:
                reports = db.query(SecurityReport).order_by(SecurityReport.generated_at.desc()).limit(20).all()
                rows = [[str(r.id), r.report_title, r.report_type, r.file_path] for r in reports]
            if not rows:
                print_info("No reports generated yet.")
                return
            render_table("SECURITY REPORTS", ["ID", "Title", "Type", "File"], rows, style="purple")
        elif sub in ("generate", "report"):
            rep = purple_intel.generate_unified_security_report()
            print_success(f"Security report compiled: {rep['report_path']}")
            print_success(f"Executive HTML report: {rep['pdf_report_path']}")
        else:
            print_warning("Usage: report [generate|list]")

    # ------------------------------------------------------------------
    # TERMINAL INTERFACE VIEWS (replace the former web dashboard screens)
    # ------------------------------------------------------------------
    @classmethod
    def _metric_panel(cls, title: str, value: str, style: str) -> Panel:
        return Panel(Text(value, style=f"bold {style}", justify="center"), title=title, border_style=style, width=24)

    @classmethod
    def _build_dashboard(cls) -> Group:
        corr = six_eyes.analyze_event_correlation()
        risk = purple_intel.calculate_risk_index()
        telem = engine_runtime.get_telemetry()
        srv = api_server.status()

        if risk["risk_level"] in ("HIGH", "CRITICAL"):
            risk_style = "red"
        elif risk["risk_level"] == "MEDIUM":
            risk_style = "yellow"
        else:
            risk_style = "cyan"
        posture_style = "green" if corr["posture_assessment"] == "SECURE" else "red"

        metrics = Columns([
            cls._metric_panel("Infinity Shield", corr["infinity_shield_status"], "cyan"),
            cls._metric_panel("Riesgo Global", f"{risk['risk_index']}/100 {risk['risk_level']}", risk_style),
            cls._metric_panel("Amenazas Activas", str(corr["active_threats"]), "red"),
            cls._metric_panel("Vulnerabilidades", str(corr["total_vulnerabilities"]), "yellow"),
            cls._metric_panel("Eventos", str(corr["total_security_events"]), "blue"),
            cls._metric_panel("Postura", corr["posture_assessment"], posture_style),
        ])

        server_text = f"API {srv['url']}" if srv["running"] else "API detenida ('server start')"
        status_line = Text.assemble(
            ("Motor: ", "dim"),
            (str(telem["status"]), "bold green" if telem["status"] == "ONLINE" else "bold yellow"),
            ("   Uptime: ", "dim"), (f"{int(telem['uptime_seconds'])}s", "white"),
            ("   Memoria: ", "dim"), (f"{telem['memory_usage_mb']} MB", "white"),
            ("   CPU: ", "dim"), (f"{telem['cpu_percent']}%", "white"),
            ("   ", ""), (server_text, "cyan" if srv["running"] else "dim"),
        )

        events = Table(title="Últimos eventos de seguridad", border_style="purple", header_style="bold purple", expand=True)
        for col in ("Hora", "Módulo", "Severidad", "Descripción"):
            events.add_column(col, overflow="fold")
        with SessionLocal() as db:
            recent = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(10).all()
            rows = [(e.created_at.strftime("%H:%M:%S"), e.origin_module, e.severity, e.description) for e in recent]
        if not rows:
            events.add_row("-", "-", "-", Text("Sin eventos registrados todavía.", style="dim"))
        for t, mod, sev, desc in rows:
            events.add_row(t, Text(mod), Text(sev, style=SEVERITY_STYLES.get(sev, "white")), Text(desc))

        parts = [
            Panel(status_line, title="[bold cyan]INDRA INFINITY ∞ — PANEL DE CONTROL[/bold cyan]", border_style="cyan"),
            metrics,
        ]
        factors = risk.get("driving_factors") or []
        if factors:
            parts.append(Panel(Text("\n".join(f"• {f}" for f in factors)), title="Factores de riesgo", border_style=risk_style))
        parts.append(events)
        return Group(*parts)

    @classmethod
    def cmd_dashboard(cls):
        console.print(cls._build_dashboard())

    @classmethod
    def cmd_monitor(cls, args: List[str]):
        try:
            interval = max(1.0, float(args[0])) if args else 2.0
        except ValueError:
            print_warning("Usage: monitor [segundos]")
            return
        print_info(f"Monitor en vivo (refresco cada {interval:g}s). Pulsa Ctrl+C para volver a la terminal.")
        try:
            with Live(cls._build_dashboard(), console=console, refresh_per_second=4, screen=False) as live:
                while True:
                    time.sleep(interval)
                    live.update(cls._build_dashboard())
        except KeyboardInterrupt:
            print_info("Monitor detenido.")

    @classmethod
    def cmd_server(cls, args: List[str]):
        sub = args[0].lower() if args else "status"
        if sub == "start":
            port = None
            if len(args) > 1:
                try:
                    port = int(args[1])
                except ValueError:
                    port = 0
                if not 1 <= port <= 65535:
                    print_error("El puerto debe ser un entero entre 1 y 65535.")
                    return
            print_info("Iniciando servidor API...")
            res = api_server.start(port)
            (print_success if res["ok"] else print_error)(res["message"])
            if res["ok"] and not settings.is_loopback_bind and not settings.API_TOKEN:
                print_warning("El servidor escucha en la red sin GOJO_API_TOKEN. Define un token en .env.")
        elif sub == "stop":
            res = api_server.stop()
            (print_success if res["ok"] else print_error)(res["message"])
        elif sub == "status":
            st = api_server.status()
            rows = [
                ["Estado", "ACTIVO" if st["running"] else "DETENIDO"],
                ["URL", st["url"] or "-"],
                ["Host / Puerto", f"{st['host']}:{st['port']}"],
                ["Token API", st["api_token"]],
                ["Documentación", f"{st['url']}/docs" if st["url"] else "-"],
            ]
            render_table("SERVIDOR API (INFINITY SHIELD)", ["Propiedad", "Valor"], rows, style="cyan")
        else:
            print_warning("Usage: server [start [puerto]|stop|status]")

    @classmethod
    def cmd_config(cls):
        rows = [
            ["Versión", settings.APP_VERSION],
            ["Entorno", settings.ENVIRONMENT],
            ["Host / Puerto API", f"{settings.HOST}:{settings.PORT}"],
            ["Token API", "configurado" if settings.API_TOKEN else "no configurado"],
            ["Hosts permitidos", ", ".join(settings.allowed_hosts)],
            ["Rate limit (req/min)", str(settings.RATE_LIMIT_REQUESTS_PER_MINUTE)],
            ["Retención historial IP", f"{settings.IP_HISTORY_RETENTION_DAYS} días"],
            ["Base de datos", settings.DATABASE_URL],
            ["Logs", str(settings.LOGS_DIR)],
            ["Reportes", str(settings.REPORTS_DIR)],
            ["Backups", str(settings.BACKUPS_DIR)],
            ["Cuarentena", str(settings.QUARANTINE_DIR)],
        ]
        render_table("CONFIGURACIÓN ACTIVA", ["Parámetro", "Valor"], rows, style="cyan")

    @classmethod
    def cmd_network_topology(cls):
        graph = NetworkMapper.generate_topology_graph()
        nodes = {n["id"]: n for n in graph["nodes"]}
        children = {}
        for edge in graph["edges"]:
            children.setdefault(edge["from"], []).append(edge)

        root_node = nodes.get("node_gojo_local")
        tree = Tree(Text(root_node["label"] if root_node else "Operador", style="bold cyan"))

        def add(branch, node_id, depth=0):
            for edge in children.get(node_id, []):
                child = nodes.get(edge["to"])
                if not child or depth > 3:
                    continue
                style = "bold blue" if child["type"] == "host" else "magenta"
                label = Text(child["label"].replace("\n", " "), style=style)
                label.append(f"  ({edge.get('label', '')})", style="dim")
                add(branch.add(label), edge["to"], depth + 1)

        add(tree, "node_gojo_local")
        if not children.get("node_gojo_local"):
            tree.add(Text("Sin hosts catalogados. Ejecuta 'blue scan <objetivo>' primero.", style="dim"))
        console.print(Panel(tree, title="[bold blue]TOPOLOGÍA DE RED[/bold blue]", border_style="blue"))

    @classmethod
    def cmd_blue_web(cls, args: List[str]):
        if not args:
            print_warning("Usage: blue web <url>")
            return
        url = args[0]
        print_info(f"Auditoría web no intrusiva sobre: {url}...")
        try:
            res = asyncio.run(blue_recon.audit_web_target(url))
        except Exception as e:
            print_error(f"Blue web audit error: {e}")
            return
        rows = [
            ["Objetivo", res["target"]],
            ["Código HTTP", str(res.get("status_code") or "-")],
            ["Servidor", res.get("server") or "-"],
            ["Tecnologías", ", ".join(res.get("technologies") or []) or "-"],
            ["Cabeceras ausentes", ", ".join(res.get("missing_security_headers") or []) or "Ninguna"],
            ["Puntuación de riesgo", str(res.get("risk_score", 0))],
        ]
        ssl_info = res.get("ssl_info")
        if ssl_info:
            rows.append(["TLS", ssl_info.get("error") or f"Expira: {ssl_info.get('expires')}"])
        if res.get("error"):
            rows.append(["Error", res["error"]])
        render_table("BLUE WEB RECON", ["Propiedad", "Resultado"], rows, style="blue")

    @classmethod
    def cmd_guide(cls, args: List[str]):
        from terminal.guides import print_module_guide, print_guide_index
        if args:
            print_module_guide(args[0])
        else:
            print_guide_index()

    @classmethod
    def cmd_update(cls, args: List[str]):
        from terminal.updater import SystemUpdater
        SystemUpdater.run_update(verbose=True)
