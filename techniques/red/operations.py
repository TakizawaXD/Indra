"""
GOJO INFINITY SECURITY ∞ — RED TECHNIQUE (OFFENSIVE AUDITING & DEFENSIVE RESPONSE)
Color Motif: Crimson Red
Executes controlled, non-destructive security audits against authorized targets and the Attack Lab.
"""

import math
import re
from typing import Dict, Any, List, Optional
import httpx

from core.logger import logger
from core.permissions import TargetAuthorizer
from core.event_engine import event_bus, EventType, SecurityEventPayload
from techniques.infinity.shield import infinity_shield
from backend.database import SessionLocal, Vulnerability, Threat

class RedOperations:
    """
    Performs authorized validation of access controls, password strength,
    HTTP configuration, and controlled injection vectors.
    """

    # Non-destructive proof-of-concept injection probes
    SQLI_PROBES = [
        "' OR '1'='1",
        "' AND '1'='2",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 1--"
    ]

    XSS_CANARY_PROBES = [
        "<script>/*gojo-infinity-canary*/</script>",
        "\"><img src=x onerror=console.log('canary')>",
        "javascript:/*infinity*/"
    ]

    @staticmethod
    def audit_password_strength(password: str) -> Dict[str, Any]:
        """Calculates password entropy, complexity, and common vulnerability flags."""
        length = len(password)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_special: pool_size += 32

        entropy = round(length * math.log2(pool_size), 2) if pool_size > 0 else 0

        # Assess strength tier
        if entropy < 36:
            tier = "VERY_WEAK"
        elif entropy < 50:
            tier = "WEAK"
        elif entropy < 65:
            tier = "MODERATE"
        elif entropy < 80:
            tier = "STRONG"
        else:
            tier = "VERY_STRONG"

        return {
            "length": length,
            "entropy_bits": entropy,
            "strength": tier,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special,
            "is_acceptable_for_admin": entropy >= 65 and length >= 12
        }

    @classmethod
    async def audit_http_methods(cls, target_url: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """Tests whether insecure HTTP methods (PUT, DELETE, TRACE) are enabled on target."""
        from urllib.parse import urlparse
        hostname = urlparse(target_url).hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        allowed_methods = []
        insecure_found = []

        async with httpx.AsyncClient(verify=False, timeout=4.0) as client:
            # Send OPTIONS request
            try:
                resp = await client.options(target_url)
                allow_header = resp.headers.get("allow", "")
                if allow_header:
                    allowed_methods = [m.strip().upper() for m in allow_header.split(",")]
            except Exception:
                pass

            # Explicit check for TRACE or dangerous methods
            for dangerous in ["TRACE", "PUT", "DELETE"]:
                try:
                    resp = await client.request(dangerous, target_url)
                    if resp.status_code not in (405, 501, 403):
                        insecure_found.append(dangerous)
                except Exception:
                    pass

        result = {
            "target": target_url,
            "allowed_methods": allowed_methods,
            "insecure_methods_exposed": insecure_found,
            "is_vulnerable": len(insecure_found) > 0
        }

        if insecure_found:
            cls._register_vulnerability(
                title=f"Insecure HTTP Methods Enabled on {hostname}",
                severity="MEDIUM",
                target=target_url,
                description=f"Target permits dangerous HTTP methods: {', '.join(insecure_found)}",
                mitigation="Disable TRACE, PUT, and DELETE methods in the web server or reverse proxy configuration."
            )

        return result

    @classmethod
    async def probe_non_destructive_sqli(cls, target_url: str, param_name: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes non-destructive boolean differential probes against an authorized target endpoint.
        Never alters or drops database content.
        """
        from urllib.parse import urlparse
        hostname = urlparse(target_url).hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        responses = []
        async with httpx.AsyncClient(verify=False, timeout=4.0) as client:
            for probe in cls.SQLI_PROBES:
                try:
                    resp = await client.get(target_url, params={param_name: probe})
                    responses.append({
                        "probe": probe,
                        "status_code": resp.status_code,
                        "length": len(resp.text),
                        "has_sql_error": bool(re.search(r"(syntax error|mysql_fetch|sqlite3|pg_query|ora-)", resp.text, re.IGNORECASE))
                    })
                except Exception as e:
                    responses.append({"probe": probe, "error": str(e)})

        vulnerable = any(r.get("has_sql_error") for r in responses)

        if vulnerable:
            cls._register_vulnerability(
                title=f"Potential SQL Injection in Parameter '{param_name}'",
                severity="HIGH",
                target=target_url,
                description=f"Probing parameter '{param_name}' provoked database error signatures.",
                mitigation="Enforce parameterized SQL queries and input validation."
            )

        return {
            "target": target_url,
            "parameter": param_name,
            "probes_executed": len(responses),
            "indication_of_sqli": vulnerable,
            "details": responses
        }

    @classmethod
    def execute_defensive_countermeasure(cls, source_ip: str, reason: str):
        """Reduces attack surface immediately in response to high-risk threats."""
        logger.warning(f"[RED RESPONSE] Activating active countermeasure against {source_ip}: {reason}")
        infinity_shield.ban_ip(source_ip, reason=f"Red Team automated countermeasure: {reason}", duration_minutes=60)

    @classmethod
    def _register_vulnerability(cls, title: str, severity: str, target: str, description: str, mitigation: str):
        try:
            with SessionLocal() as db:
                vuln = Vulnerability(
                    title=title,
                    severity=severity,
                    target=target,
                    status="confirmed",
                    description=description,
                    mitigation=mitigation
                )
                db.add(vuln)
                db.commit()

            event_bus.emit(SecurityEventPayload(
                event_type=EventType.VULNERABILITY_FOUND,
                origin_module="RED",
                category="AUDIT_FINDING",
                severity=severity,
                description=title,
                target=target,
                action_taken="VULNERABILITY_CATALOGED"
            ))
        except Exception as e:
            logger.error(f"Failed to record red vulnerability finding: {e}")

# Singleton Red Operations Instance
red_operations = RedOperations()
