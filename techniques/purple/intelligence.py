"""
GOJO INFINITY SECURITY ∞ — PURPLE TECHNIQUE (CORRELATION & INCIDENT INTELLIGENCE)
Color Motif: Electric Purple
Synthesizes offensive Blue/Red insights with defensive Infinity Shield protection.
"""

from core.timeutils import utcnow
from typing import Dict, Any
import json

from core.logger import logger
from core.config import settings
from backend.database import SessionLocal, Vulnerability, Threat, Host, Port, FirewallRule, SecurityReport

class PurpleIntelligence:
    """
    Correlates telemetry across all branches:
    - Calculates systemic Risk Index (0-100)
    - Recommends defensive mitigations for verified red findings
    - Assembles unified audit reports
    """

    @classmethod
    def calculate_risk_index(cls) -> Dict[str, Any]:
        """Calculates dynamic risk score based on real database records."""
        with SessionLocal() as db:
            vulns = db.query(Vulnerability).all()
            threats = db.query(Threat).filter(Threat.status == "active").all()
            open_ports = db.query(Port).all()

        score = 0
        factors = []

        # Weigh vulnerabilities
        for v in vulns:
            sev = v.severity.upper()
            if sev == "CRITICAL":
                score += 25
                factors.append(f"Critical Vulnerability: {v.title}")
            elif sev == "HIGH":
                score += 15
                factors.append(f"High Vulnerability: {v.title}")
            elif sev == "MEDIUM":
                score += 8
            elif sev == "LOW":
                score += 3

        # Weigh active threats
        for t in threats:
            score += 10
            factors.append(f"Active Threat: {t.threat_type} from {t.source_ip}")

        # Weigh exposed open ports
        risky_ports = [21, 23, 445, 3389, 5900, 27017]
        for p in open_ports:
            if p.port_number in risky_ports:
                score += 12
                factors.append(f"High-risk administrative port exposed: {p.port_number} ({p.service_name})")

        normalized_score = min(100, max(0, score))

        if normalized_score >= 70:
            level = "CRITICAL"
        elif normalized_score >= 45:
            level = "HIGH"
        elif normalized_score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_index": normalized_score,
            "risk_level": level,
            "total_vulnerabilities": len(vulns),
            "active_threats": len(threats),
            "open_ports_cataloged": len(open_ports),
            "driving_factors": factors[:5]
        }

    @classmethod
    def generate_unified_security_report(
        cls,
        project_name: str = "Default_Audit",
        report_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """Compiles a complete audit report and writes Markdown + JSON to `reports/`."""
        timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
        report_filename = f"Gojo_Infinity_Report_{timestamp}.md"
        report_path = settings.REPORTS_DIR / report_filename

        risk_data = cls.calculate_risk_index()

        with SessionLocal() as db:
            vulns = db.query(Vulnerability).all()
            threats = db.query(Threat).all()
            hosts = db.query(Host).all()
            rules = db.query(FirewallRule).filter(FirewallRule.is_active == True).all()

        report_content = f"""# GOJO INFINITY SECURITY ∞ — EXECUTIVE AUDIT REPORT
**Generated:** {utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Project:** {project_name}  
**Creator / Architect:** {settings.CREATOR}  
**Organization / Target:** {settings.TARGET_ENTITY}  
**Classification:** RESTRICTED / INTERNAL AUDIT  
**Risk Level:** {risk_data['risk_level']} (Index: {risk_data['risk_index']}/100)  

---

## 1. EXECUTIVE POSTURE SUMMARY
The automated Six Eyes correlation engine evaluated network topology, active threats, and audit findings.
- **Overall Threat Level:** {risk_data['risk_level']}
- **Cataloged Vulnerabilities:** {risk_data['total_vulnerabilities']}
- **Active Threats Neutralized:** {len(threats)}
- **Discovered Network Hosts:** {len(hosts)}
- **Active Infinity Shield Rules:** {len(rules)}

---

## 2. IDENTIFIED VULNERABILITIES
"""
        if not vulns:
            report_content += "\n*No vulnerabilities cataloged at this time.*\n"
        else:
            for v in vulns:
                report_content += f"""
### [{v.severity}] {v.title}
- **Target:** `{v.target}`
- **CVSS Score:** {v.cvss_score} | **Status:** {v.status}
- **Description:** {v.description}
- **Mitigation:** {v.mitigation or 'Apply security updates and restrict endpoint access.'}
"""

        report_content += """
---

## 3. INFINITY SHIELD ACTIVE DEFENSES
"""
        if not rules:
            report_content += "\n*No custom firewall rules currently active.*\n"
        else:
            for r in rules:
                report_content += f"- **Rule:** `{r.rule_name}` | **Type:** `{r.rule_type}` | **Target:** `{r.target_pattern}` | **Hits:** {r.hits}\n"

        report_content += """
---
*Report generated automatically by GOJO INFINITY SECURITY ∞ — "Nothing gets through Infinity."*
"""

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Also compile official Indra corporate printable report
        try:
            from techniques.purple.pdf_report import IndraReportGenerator
            pdf_path = IndraReportGenerator.generate_indra_report(project_name=project_name, risk_data=risk_data)
        except Exception as e:
            logger.debug(f"Corporate PDF report generation note: {e}")
            pdf_path = str(report_path)

        # Persist report reference to DB
        report_title = f"Security Audit - {project_name} ({timestamp})"
        with SessionLocal() as db:
            rep = SecurityReport(
                report_title=report_title,
                report_type=report_type,
                file_path=pdf_path or str(report_path),
                summary_json=json.dumps(risk_data)
            )
            db.add(rep)
            db.commit()

        logger.info(f"[PURPLE INTELLIGENCE] Unified report generated: {report_path}")
        return {
            "report_title": report_title,
            "report_path": str(report_path),
            "pdf_report_path": pdf_path,
            "risk_data": risk_data
        }

# Global Purple Intelligence instance
purple_intel = PurpleIntelligence()
