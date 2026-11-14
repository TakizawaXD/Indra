"""
GOJO INFINITY SECURITY ∞ — TERMINAL COMMAND HANDLER
Dispatches all CLI commands to underlying modules with Rich formatting.
"""

import asyncio
from typing import List

from rich.markup import escape
from rich.panel import Panel

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
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from laboratory.web_lab import AttackLabSimulator
from laboratory.scenarios import LAB_SCENARIOS
from vulnerability.cve import CVEIntelligence, OFFLINE_CVE_FEED
from backend.database import SessionLocal, SecurityEvent, Vulnerability, Threat, Incident, SecurityReport


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
            "dashboard": lambda: console.print(
                f"[bold cyan]Panel local disponible en:[/bold cyan] http://{settings.HOST}:{settings.PORT}"
            ),
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
            ["status", "[bold purple][AMBAS][/bold purple]", "Telemetría en tiempo real de CPU, memoria y módulos activos"],
            ["infinity [status|rules|ban <ip>|unban <ip>]", "[bold cyan][DEFENSA][/bold cyan]", "Firewall WAF multicapa, rate limiter y bloqueo de IPs"],
            ["blue scan <target> [ports...]", "[bold red][ATAQUE][/bold red]", "Reconocimiento y escaneo TCP de puertos y servicios"],
            ["red [audit pass <clave>|audit-methods <url>]", "[bold red][ATAQUE][/bold red]", "Auditoría de fortaleza de claves y métodos HTTP"],
            ["purple [risk|quarantine|report]", "[bold purple][AMBAS][/bold purple]", "Cálculo de riesgo (0-100), bóveda de cuarentena e informes"],
            ["sixeyes [status|ask <pregunta>]", "[bold purple][AMBAS][/bold purple]", "Asesor cognitivo offline de ciberseguridad"],
            ["hollow-purple <target>", "[bold purple][AMBAS][/bold purple]", "Protocolo definitivo de convergencia en 5 fases"],
            ["network [diagnostics|subnet <cidr>|dns <dominio>]", "[bold cyan][DEFENSA][/bold cyan]", "Diagnóstico de interfaces de red locales y subredes"],
            ["ip [lookup <ip>|history|export]", "[bold cyan][DEFENSA][/bold cyan]", "Consulta de reputación de IPs y visitas informadas"],
            ["vulnerability [list|cve <componente>]", "[bold purple][AMBAS][/bold purple]", "Catálogo de vulnerabilidades y base CVE offline"],
            ["threats | incidents | logs", "[bold purple][AMBAS][/bold purple]", "Amenazas, incidentes y flujo de eventos recientes"],
            ["lab [list|sqli <p>|xss <p>|auth <u> <clave>]", "[bold red][ATAQUE][/bold red]", "Laboratorio seguro de práctica en memoria (SQLi/XSS)"],
            ["report [generate|list]", "[bold purple][AMBAS][/bold purple]", "Compilación de informes ejecutivos en Markdown y HTML"],
            ["exit / quit", "[dim]SISTEMA[/dim]", "Salir de Indra Terminal"]
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
        rest = args[1:] if args and args[0].lower() == "scan" else args
        if not rest:
            print_warning("Usage: blue scan <target> [ports...]")
            return
        target = rest[0]
        try:
            ports = sorted({int(p) for p in rest[1:]}) or None
        except ValueError:
            ports = [-1]
        if ports and any(p < 1 or p > 65535 for p in ports):
            print_error("Ports must be integers between 1 and 65535.")
            return

        print_info(f"Initiating Blue Reconnaissance on: {target}...")
        try:
            results = asyncio.run(blue_recon.scan_target_ports_and_save(target, ports=ports))
        except Exception as e:
            print_error(f"Blue scan error: {e}")
            return
        if not results:
            print_info("No open TCP ports detected on this target.")
            return
        rows = [[str(r["port"]), r["protocol"], r["state"], r["service"], r["banner"] or ""] for r in results]
        render_table(f"BLUE RECON RESULTS: {target}", ["Port", "Proto", "State", "Service", "Banner"], rows, style="blue")

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
        else:
            print_warning("Usage: red audit pass <password> | red audit-methods <url>")

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
