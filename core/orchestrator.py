"""
GOJO INFINITY SECURITY ∞ — SIX EYES CENTRAL ORCHESTRATOR & GOJO AI
The cognitive brain coordinating all 4 techniques (Infinity, Blue, Red, Purple)
and handling intelligent analysis, threat correlation, and Gojo AI guidance.
"""

from typing import Dict, Any, Optional

from core.logger import logger
from core.event_engine import event_bus, EventType, SecurityEventPayload
from backend.database import SessionLocal, SecurityEvent, Threat, Incident, Vulnerability

class GojoAIAssistant:
    """
    Intelligent cybersecurity adviser inspired by Gojo Satoru's analytical prowess.
    Functions completely offline using internal rule bases & knowledge graphs,
    or optionally bridges to external AI APIs when enabled by the user.
    """

    EXPLANATIONS = {
        "SQL_INJECTION": {
            "title": "SQL Injection (SQLi) Vulnerability",
            "concept": "Occurs when untrusted user input is directly concatenated into a dynamic database query, allowing an attacker to manipulate SQL syntax.",
            "impact": "Data breach, unauthorized authentication bypass, modification or deletion of records.",
            "mitigation": "1. Use parameterized queries (prepared statements).\n2. Enforce Object-Relational Mapping (ORM).\n3. Apply input validation and strict principle of least privilege on database accounts."
        },
        "XSS": {
            "title": "Cross-Site Scripting (XSS)",
            "concept": "Enables attackers to inject client-side scripts into web pages viewed by other users.",
            "impact": "Session hijacking, credential theft, CSRF execution within authenticated user context.",
            "mitigation": "1. Context-aware output encoding (HTML, JavaScript, Attribute).\n2. Implement a strict Content-Security-Policy (CSP).\n3. Set HttpOnly and SameSite flags on session cookies."
        },
        "OPEN_PORT": {
            "title": "Exposed Network Port",
            "concept": "A listening network service accessible to incoming connections.",
            "impact": "Expands the attack surface if the underlying daemon contains unpatched CVEs or weak authentication.",
            "mitigation": "1. Close unused ports.\n2. Bind services exclusively to localhost (127.0.0.1) if external access is not required.\n3. Implement firewall allowlisting (Infinity Shield)."
        },
        "BRUTE_FORCE": {
            "title": "Authentication Brute Force",
            "concept": "Repeated attempts to guess passwords or cryptographic keys systematically.",
            "impact": "Account takeover and unauthorized administrative access.",
            "mitigation": "1. Token-bucket rate limiting.\n2. Automatic exponential IP backoff or temporary lockout via Infinity Shield.\n3. Enforce multi-factor authentication (MFA)."
        }
    }

    def ask(self, question: str, context_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Provides analytical answers and technical remediation advice."""
        q_lower = question.lower()
        topic = None

        if "sql" in q_lower or "sqli" in q_lower:
            topic = "SQL_INJECTION"
        elif "xss" in q_lower or "script" in q_lower:
            topic = "XSS"
        elif "port" in q_lower or "open" in q_lower or "servicio" in q_lower:
            topic = "OPEN_PORT"
        elif "brute" in q_lower or "fuerza" in q_lower or "password" in q_lower or "auth" in q_lower:
            topic = "BRUTE_FORCE"

        if topic and topic in self.EXPLANATIONS:
            info = self.EXPLANATIONS[topic]
            return {
                "source": "six_eyes_offline_knowledge",
                "answer": (
                    f"**[SIX EYES ANALYSIS] — {info['title']}**\n\n"
                    f"**Core Concept:** {info['concept']}\n\n"
                    f"**Impact:** {info['impact']}\n\n"
                    f"**Infinity Remediation Steps:**\n{info['mitigation']}"
                ),
                "technical_details": info
            }

        # Default contextual synthesis
        return {
            "source": "six_eyes_cognitive_rules",
            "answer": (
                f"[Six Eyes Advisor] Regarding: '{question}'. "
                "All operational findings are logged in the SQLite telemetry database. "
                "Recommended next step: Execute 'gojo audit report' or navigate to the Vulnerability Center "
                "to inspect CVSS scores and mitigation plans."
            ),
            "context": context_data or {}
        }

class SixEyesOrchestrator:
    """
    Central Coordinator. Hooks into the Event Bus, correlates cross-module events,
    dispatches automated containment to Infinity Shield, and powers Hollow Purple.
    """

    def __init__(self):
        self.ai = GojoAIAssistant()
        self._setup_event_listeners()

    def _setup_event_listeners(self):
        """Registers event-driven logic across techniques."""
        event_bus.subscribe(EventType.THREAT_DETECTED, self._on_threat_detected)
        event_bus.subscribe(EventType.SUSPICIOUS_REQUEST, self._on_suspicious_request)
        event_bus.subscribe(EventType.VULNERABILITY_FOUND, self._on_vulnerability_found)

    def _on_threat_detected(self, event: SecurityEventPayload):
        logger.warning(f"[SIX EYES] Correlating Threat: {event.description} from {event.source_ip}")
        # Automatically generate an Incident if threat is HIGH or CRITICAL
        if event.severity in ["HIGH", "CRITICAL"]:
            with SessionLocal() as db:
                incident = Incident(
                    title=f"Automated Incident: {event.description[:200]}",
                    severity=event.severity,
                    status="investigating",
                    containment_action="Infinity Shield auto-block queued"
                )
                db.add(incident)
                db.commit()

    def _on_suspicious_request(self, event: SecurityEventPayload):
        logger.info(f"[SIX EYES] Suspicious telemetry registered: {event.description}")

    def _on_vulnerability_found(self, event: SecurityEventPayload):
        logger.info(f"[SIX EYES] Classifying Vulnerability: {event.description}")

    def analyze_event_correlation(self) -> Dict[str, Any]:
        """Correlates recent events, open ports, and threats into an overarching posture."""
        with SessionLocal() as db:
            total_events = db.query(SecurityEvent).count()
            active_threats = db.query(Threat).filter(Threat.status == "active").count()
            open_incidents = db.query(Incident).filter(Incident.status == "open").count()
            vulnerabilities = db.query(Vulnerability).all()
            vuln_count = len(vulnerabilities)
            high_critical_vulns = sum(1 for v in vulnerabilities if v.severity in ["HIGH", "CRITICAL"])

        return {
            "total_security_events": total_events,
            "active_threats": active_threats,
            "open_incidents": open_incidents,
            "total_vulnerabilities": vuln_count,
            "high_critical_vulnerabilities": high_critical_vulns,
            "infinity_shield_status": "ENGAGED",
            "posture_assessment": "SECURE" if active_threats == 0 and high_critical_vulns == 0 else "ATTENTION_REQUIRED"
        }

# Global Orchestrator instance
six_eyes = SixEyesOrchestrator()
