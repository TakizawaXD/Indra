"""
GOJO INFINITY SECURITY ∞ — TERMINAL COMMAND HANDLER
Dispatches all CLI commands to underlying modules with Rich formatting.
"""

import asyncio
from typing import List
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
from network.ports import PortScanner
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from laboratory.web_lab import AttackLabSimulator
from laboratory.scenarios import LAB_SCENARIOS
from backend.database import SessionLocal, SecurityEvent, Vulnerability, Threat, Incident

class GojoCommandHandler:
    """Dispatches Gojo terminal commands to functional subsystems."""

    @classmethod
    def execute(cls, cmd_line: str):
        parts = cmd_line.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            cls.cmd_help(args)
        elif cmd == "status":
            cls.cmd_status()
        elif cmd == "version":
            console.print("[bold cyan]Indra Infinity Security ∞[/bold cyan] v1.0.0 (Para: Indra | Creador: Takizawa)")
        elif cmd == "dashboard":
            console.print("[bold cyan]Panel local disponible en:[/bold cyan] http://127.0.0.1:8000")
        elif cmd == "infinity":
            cls.cmd_infinity(args)
        elif cmd == "blue":
            cls.cmd_blue(args)
        elif cmd == "red":
            cls.cmd_red(args)
        elif cmd == "purple":
            cls.cmd_purple(args)
        elif cmd == "sixeyes":
            cls.cmd_sixeyes(args)
        elif cmd in ("hollow-purple", "hollow_purple"):
            cls.cmd_hollow_purple(args)
        elif cmd == "network":
            cls.cmd_network(args)
        elif cmd == "ip":
            cls.cmd_ip(args)
        elif cmd == "audit":
            cls.cmd_audit(args)
        elif cmd == "vulnerability":
            cls.cmd_vulnerability(args)
        elif cmd == "protect" or cmd == "firewall":
            cls.cmd_firewall(args)
        elif cmd == "threats":
            cls.cmd_threats()
        elif cmd == "incidents":
            cls.cmd_incidents()
        elif cmd == "logs":
            cls.cmd_logs(args)
        elif cmd == "lab":
            cls.cmd_lab(args)
        elif cmd == "report":
            cls.cmd_report(args)
        else:
            print_warning(f"Unknown command: '{cmd}'. Type 'help' for available commands.")

    @classmethod
    def cmd_help(cls, args: List[str]):
        print_banner()
        console.print("[bold cyan][DEFENSA][/bold cyan]: Proteger y bloquear | [bold red][ATAQUE][/bold red]: Auditar y evaluar | [bold purple][AMBAS][/bold purple]: Correlación y convergencia\n")
        table_rows = [
            ["status", "[bold purple][AMBAS][/bold purple]", "Telemetría en tiempo real de CPU, memoria y módulos activos"],
            ["infinity [rules|ban|unban]", "[bold cyan][DEFENSA][/bold cyan]", "Firewall WAF multicapa, rate limiter y bloqueo de IPs"],
            ["blue scan <target> [ports...]", "[bold red][ATAQUE][/bold red]", "Reconocimiento y escaneo TCP de puertos y servicios"],
            ["red [audit-auth|audit-methods]", "[bold red][ATAQUE][/bold red]", "Auditoría de fortaleza de claves y métodos HTTP"],
            ["purple [risk|quarantine|report]", "[bold purple][AMBAS][/bold purple]", "Cálculo de riesgo (0-100), bóveda de cuarentena e informes"],
            ["sixeyes [status|ask <pregunta>]", "[bold purple][AMBAS][/bold purple]", "Asesor cognitivo offline de ciberseguridad"],
            ["hollow-purple <target>", "[bold purple][AMBAS][/bold purple]", "Protocolo definitivo de convergencia en 5 fases"],
            ["network [diagnostics|subnet|dns]", "[bold cyan][DEFENSA][/bold cyan]", "Diagnóstico de interfaces de red locales y subredes"],
            ["ip [lookup <ip>|history|export]", "[bold cyan][DEFENSA][/bold cyan]", "Consulta de reputación de IPs y visitas informadas"],
            ["vulnerability [list|cve <query>]", "[bold purple][AMBAS][/bold purple]", "Catálogo de vulnerabilidades y base CVE offline"],
            ["lab [list|sqli|xss|auth]", "[bold red][ATAQUE][/bold red]", "Laboratorio seguro de práctica en memoria (SQLi/XSS)"],
            ["report [generate|list]", "[bold purple][AMBAS][/bold purple]", "Compilación de informes ejecutivos en Markdown y JSON"],
            ["exit / quit", "[dim]SISTEMA[/dim]", "Salir de Gojo Terminal"]
        ]
        render_table("MATRIZ DE COMANDOS GOJO INFINITY", ["Comando", "Propósito", "Descripción Operativa"], table_rows, style="cyan")

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
        sub = args[0].lower() if args else "rules"
        if sub == "rules":
            rules = infinity_shield.get_active_rules()
            if not rules:
                print_info("No active IP ban rules. Infinity Shield is monitoring in real-time.")
                return
            rows = [[str(r["id"]), r["name"], r["type"], r["target"], str(r["hits"]), r["expires_at"]] for r in rules]
            render_table("INFINITY SHIELD ACTIVE RULES", ["ID", "Name", "Type", "Target", "Hits", "Expires"], rows, style="cyan")
        elif sub == "ban" and len(args) > 1:
            ip = args[1]
            infinity_shield.ban_ip(ip, reason="Manual operator ban from Gojo Terminal", duration_minutes=60)
            print_success(f"IP {ip} banned for 60 minutes.")
        elif sub == "unban" and len(args) > 1:
            ip = args[1]
            if infinity_shield.unban_ip(ip):
                print_success(f"IP {ip} unbanned.")
            else:
                print_warning(f"No active ban found for {ip}.")

    @classmethod
    def cmd_blue(cls, args: List[str]):
        if not args:
            print_warning("Usage: blue scan <target> [ports...]")
            return
        target = args[1] if args[0] == "scan" and len(args) > 1 else args[0]
        print_info(f"Initiating Blue Reconnaissance on: {target}...")
        try:
            results = asyncio.run(blue_recon.scan_target_ports_and_save(target))
            rows = [[str(r["port"]), r["protocol"], r["state"], r["service"], r["banner"] or ""] for r in results]
            render_table(f"BLUE RECON RESULTS: {target}", ["Port", "Proto", "State", "Service", "Banner"], rows, style="blue")
        except Exception as e:
            print_error(f"Blue scan error: {e}")

    @classmethod
    def cmd_red(cls, args: List[str]):
        sub = args[0] if args else "help"
        if sub == "audit-auth" and len(args) > 1:
            pw = args[1]
            res = red_operations.audit_password_strength(pw)
            rows = [
                ["Length", str(res["length"])],
                ["Entropy", f"{res['entropy_bits']} bits"],
                ["Strength Tier", res["strength"]],
                ["Admin Grade", "YES" if res["is_acceptable_for_admin"] else "NO (Insufficient)"]
            ]
            render_table("PASSWORD STRENGTH AUDIT", ["Metric", "Assessment"], rows, style="red")
        elif sub == "audit-methods" and len(args) > 1:
            url = args[1]
            res = asyncio.run(red_operations.audit_http_methods(url))
            print_info(f"Allowed Methods: {res.get('allowed_methods')}")
            if res.get("insecure_methods_exposed"):
                print_warning(f"Dangerous Methods Exposed: {res['insecure_methods_exposed']}")
            else:
                print_success("No dangerous HTTP methods exposed.")

    @classmethod
    def cmd_purple(cls, args: List[str]):
        sub = args[0] if args else "risk"
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
            rep = purple_intel.generate_unified_security_report()
            print_success(f"Report generated: {rep['report_path']}")

    @classmethod
    def cmd_sixeyes(cls, args: List[str]):
        if args and args[0] == "ask":
            query = " ".join(args[1:])
            res = six_eyes.ai.ask(query)
            console.print(Panel(res["answer"], title="[bold cyan]SIX EYES ADVISOR[/bold cyan]", border_style="cyan"))
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
        sub = args[0] if args else "diagnostics"
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

    @classmethod
    def cmd_ip(cls, args: List[str]):
        sub = args[0] if args else "history"
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
            rows = [[h["ip"], h["path"], h["consent"], h["timestamp"]] for h in history]
            render_table("IP LOGGER INFORMED VISITS", ["IP Address", "Endpoint", "Consent", "Timestamp"], rows, style="cyan")

    @classmethod
    def cmd_lab(cls, args: List[str]):
        sub = args[0] if args else "list"
        if sub == "list":
            rows = [[s["id"], s["title"], s["category"], s["difficulty"]] for s in LAB_SCENARIOS.values()]
            render_table("SAFE ATTACK LAB SCENARIOS", ["Scenario ID", "Title", "Category", "Difficulty"], rows, style="green")
        elif sub == "sqli" and len(args) > 1:
            payload = " ".join(args[1:])
            res = AttackLabSimulator.test_sqli_endpoint(payload)
            print_info(f"Simulated Query: {res['simulated_query']}")
            print_warning(f"Detection Status: {res['status'].upper()}")
            print_info(f"Rows Returned: {len(res['records_returned'])}")
        elif sub == "xss" and len(args) > 1:
            payload = " ".join(args[1:])
            res = AttackLabSimulator.test_xss_endpoint(payload)
            print_warning(f"Detection Status: {res['status'].upper()}")
            print_info(f"Reflected: {res['reflected_html']}")

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
        with SessionLocal() as db:
            vulns = db.query(Vulnerability).all()
            if not vulns:
                print_success("Zero vulnerabilities cataloged.")
                return
            rows = [[str(v.id), v.title[:35], v.severity, str(v.cvss_score), v.status, v.target[:25]] for v in vulns]
            render_table("VULNERABILITY CENTER", ["ID", "Title", "Severity", "CVSS", "Status", "Target"], rows, style="yellow")

    @classmethod
    def cmd_report(cls, args: List[str]):
        rep = purple_intel.generate_unified_security_report()
        print_success(f"Security report compiled: {rep['report_path']}")
