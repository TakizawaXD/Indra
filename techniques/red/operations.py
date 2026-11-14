"""
GOJO INFINITY SECURITY ∞ — RED TECHNIQUE (OFFENSIVE AUDITING & DEFENSIVE RESPONSE)
Color Motif: Crimson Red
Executes controlled, non-destructive security audits against authorized targets and the Attack Lab.
"""

import math
import re
from typing import Dict, Any, Optional
import httpx

from core.logger import logger
from core.permissions import TargetAuthorizer
from core.event_engine import event_bus, EventType, SecurityEventPayload
from techniques.infinity.shield import infinity_shield
from backend.database import SessionLocal, Vulnerability

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

    # Security headers evaluated during a deep web audit, with the weight of their absence.
    SECURITY_HEADERS = {
        "strict-transport-security": 15,
        "content-security-policy": 20,
        "x-content-type-options": 10,
        "x-frame-options": 10,
        "referrer-policy": 5,
        "permissions-policy": 5,
    }

    # Read-only existence probes for commonly exposed sensitive artifacts (GET only, never modified).
    SENSITIVE_PATHS = [
        "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak", "/config.php.bak",
        "/backup.zip", "/backup.sql", "/db.sql", "/.aws/credentials", "/phpinfo.php",
        "/server-status", "/actuator/health", "/actuator/env", "/.DS_Store",
        "/robots.txt", "/admin/", "/.svn/entries", "/web.config", "/id_rsa",
    ]

    # Reflected-XSS canary that is harmless if reflected (comment node, no execution sink needed to detect).
    XSS_CANARY = "gojoinfxss<svg/onload=1>"

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
    async def audit_security_headers(cls, target_url: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """Scores a target's HTTP security headers and cookie flags (read-only GET)."""
        from urllib.parse import urlparse
        hostname = urlparse(target_url).hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        missing, present, weak = [], [], []
        penalty = 0
        cookie_issues = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                resp = await client.get(target_url)
            lowered = {k.lower(): v for k, v in resp.headers.items()}
            for header, weight in cls.SECURITY_HEADERS.items():
                if header in lowered:
                    present.append(header)
                else:
                    missing.append(header)
                    penalty += weight
            # Cookie flag inspection
            for cookie in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
                low = cookie.lower()
                if "secure" not in low:
                    cookie_issues.append("cookie sin Secure")
                if "httponly" not in low:
                    cookie_issues.append("cookie sin HttpOnly")
                if "samesite" not in low:
                    cookie_issues.append("cookie sin SameSite")
            server = lowered.get("server")
            if server and any(c.isdigit() for c in server):
                weak.append(f"Server revela versión: {server}")
                penalty += 5
        except Exception as e:
            return {"target": target_url, "error": str(e)}

        score = min(100, penalty)
        if missing:
            cls._register_vulnerability(
                title=f"Cabeceras de seguridad ausentes en {hostname}",
                severity="MEDIUM" if score < 40 else "HIGH",
                target=target_url,
                description=f"Faltan cabeceras: {', '.join(missing)}. Problemas de cookies: {', '.join(set(cookie_issues)) or 'ninguno'}.",
                mitigation="Añadir HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy y flags Secure/HttpOnly/SameSite.",
            )
        return {
            "target": target_url,
            "present_headers": present,
            "missing_headers": missing,
            "weaknesses": weak + list(set(cookie_issues)),
            "hardening_penalty": score,
        }

    @classmethod
    async def probe_sensitive_paths(cls, target_url: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """Read-only existence check for commonly exposed sensitive files (GET only, no modification)."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        base = f"{parsed.scheme or 'http'}://{parsed.netloc or hostname}"
        exposed = []
        import asyncio
        sem = asyncio.Semaphore(8)

        async def check(path: str, client):
            url = urljoin(base + "/", path.lstrip("/"))
            async with sem:
                try:
                    resp = await client.get(url)
                    # Flag only clear exposure: a 2xx with real content (not a soft-404 page).
                    if resp.status_code == 200 and len(resp.content) > 0:
                        exposed.append({"path": path, "status": resp.status_code, "bytes": len(resp.content)})
                except Exception:
                    pass

        try:
            async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=False) as client:
                await asyncio.gather(*[check(p, client) for p in cls.SENSITIVE_PATHS])
        except Exception as e:
            return {"target": base, "error": str(e)}

        sensitive = [e for e in exposed if e["path"] not in ("/robots.txt",)]
        if sensitive:
            cls._register_vulnerability(
                title=f"Archivos sensibles expuestos en {hostname}",
                severity="HIGH",
                target=base,
                description=f"Accesibles sin autenticación: {', '.join(e['path'] for e in sensitive)}",
                mitigation="Bloquear o eliminar estos recursos del servidor web y restringir el acceso por configuración.",
            )
        return {"target": base, "paths_tested": len(cls.SENSITIVE_PATHS), "exposed": exposed}

    @classmethod
    async def probe_reflected_xss(cls, target_url: str, param_name: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """Sends a harmless canary and checks whether it is reflected unencoded (non-destructive GET)."""
        from urllib.parse import urlparse
        hostname = urlparse(target_url).hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        reflected_raw = False
        try:
            async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=True) as client:
                resp = await client.get(target_url, params={param_name: cls.XSS_CANARY})
            reflected_raw = cls.XSS_CANARY in resp.text  # unencoded reflection = likely XSS
        except Exception as e:
            return {"target": target_url, "parameter": param_name, "error": str(e)}

        if reflected_raw:
            cls._register_vulnerability(
                title=f"XSS reflejado probable en parámetro '{param_name}'",
                severity="HIGH",
                target=target_url,
                description=f"El canario '{cls.XSS_CANARY}' se reflejó sin codificar en la respuesta.",
                mitigation="Codificar la salida según contexto (HTML/atributo/JS) y aplicar una CSP estricta.",
            )
        return {"target": target_url, "parameter": param_name, "reflected_unencoded": reflected_raw}

    @classmethod
    async def deep_web_audit(cls, target_url: str, param_name: Optional[str] = None, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Runs the full non-destructive offensive audit chain against an AUTHORIZED target:
        security headers, cookie flags, HTTP methods, sensitive-path exposure and
        (if a parameter is given) boolean SQLi + reflected-XSS canaries.
        Aggregates every finding into a single prioritized risk score.
        """
        from urllib.parse import urlparse
        hostname = urlparse(target_url).hostname or target_url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        findings: Dict[str, Any] = {"target": target_url}
        score = 0

        headers = await cls.audit_security_headers(target_url, project_id=project_id)
        findings["security_headers"] = headers
        score += min(40, headers.get("hardening_penalty", 0) // 2)

        methods = await cls.audit_http_methods(target_url, project_id=project_id)
        findings["http_methods"] = methods
        if methods.get("is_vulnerable"):
            score += 15

        paths = await cls.probe_sensitive_paths(target_url, project_id=project_id)
        findings["sensitive_paths"] = paths
        score += 20 * len([p for p in paths.get("exposed", []) if p["path"] != "/robots.txt"])

        if param_name:
            sqli = await cls.probe_non_destructive_sqli(target_url, param_name, project_id=project_id)
            findings["sqli"] = sqli
            if sqli.get("indication_of_sqli"):
                score += 30
            xss = await cls.probe_reflected_xss(target_url, param_name, project_id=project_id)
            findings["reflected_xss"] = xss
            if xss.get("reflected_unencoded"):
                score += 25

        score = min(100, score)
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW"
        findings["risk_score"] = score
        findings["risk_level"] = level

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.AUDIT_COMPLETED,
            origin_module="RED",
            category="DEEP_WEB_AUDIT",
            severity="HIGH" if score >= 45 else "INFO",
            description=f"Auditoría profunda sobre {target_url} completada. Riesgo {level} ({score}/100).",
            target=target_url,
            evidence={"risk_score": score},
        ))
        return findings

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
