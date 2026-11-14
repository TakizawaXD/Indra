"""
GOJO INFINITY SECURITY ∞ — BLUE TECHNIQUE (RECONNAISSANCE & SURFACE INTELLIGENCE)
Color Motif: Deep Blue
Uncovers, analyzes, and catalogs the authorized attack surface.
"""

import ssl
import socket
from typing import Dict, Any, List, Optional
import httpx

from core.permissions import TargetAuthorizer
from core.event_engine import event_bus, EventType, SecurityEventPayload
from network.ports import PortScanner
from backend.database import SessionLocal, Host, Port, NetworkScan

class BlueReconnaissance:
    """
    Coordinates port scans, DNS intelligence, and web asset reconnaissance.
    Strictly restricted to authorized targets.
    """

    RECOMMENDED_SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    @classmethod
    async def audit_web_target(cls, url: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Performs non-invasive web surface reconnaissance:
        - HTTP status and redirects
        - Server and technology fingerprinting from headers and cookies
        - Missing security headers analysis
        - SSL/TLS certificate validity
        """
        # Parse host for authorization check
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        TargetAuthorizer.assert_authorized(hostname, project_id=project_id)

        findings: Dict[str, Any] = {
            "target": url,
            "status_code": None,
            "server": "Unknown",
            "technologies": [],
            "present_headers": {},
            "missing_security_headers": [],
            "ssl_info": None,
            "risk_score": 0
        }

        # 1. HTTP Inspection
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                resp = await client.get(url if url.startswith("http") else f"http://{url}")
                findings["status_code"] = resp.status_code
                findings["present_headers"] = dict(resp.headers)

                # Technology Detection via Headers
                server_hdr = resp.headers.get("server")
                if server_hdr:
                    findings["server"] = server_hdr
                    findings["technologies"].append(f"Server: {server_hdr}")

                x_powered = resp.headers.get("x-powered-by")
                if x_powered:
                    findings["technologies"].append(f"Framework: {x_powered}")

                # Security Header Analysis
                for sec_header in cls.RECOMMENDED_SECURITY_HEADERS:
                    if sec_header.lower() not in [h.lower() for h in resp.headers.keys()]:
                        findings["missing_security_headers"].append(sec_header)
                        findings["risk_score"] += 10
        except Exception as e:
            findings["error"] = str(e)

        # 2. SSL/TLS Certificate Verification if HTTPS
        if "https://" in url or parsed.scheme == "https" or parsed.port == 443:
            try:
                ssl_ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                    with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        findings["ssl_info"] = {
                            "subject": dict(x[0] for x in cert.get("subject", ())),
                            "issuer": dict(x[0] for x in cert.get("issuer", ())),
                            "version": cert.get("version"),
                            "expires": cert.get("notAfter")
                        }
            except Exception as e:
                findings["ssl_info"] = {"error": f"SSL inspection error: {e}"}

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.AUDIT_COMPLETED,
            origin_module="BLUE",
            category="WEB_RECON",
            severity="INFO" if findings["risk_score"] < 30 else "LOW",
            description=f"Web reconnaissance on {url} completed. Missing headers: {len(findings['missing_security_headers'])}",
            target=url,
            evidence=findings
        ))

        return findings

    @classmethod
    async def scan_target_ports_and_save(
        cls,
        target: str,
        project_id: Optional[int] = None,
        ports: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """Scans ports on target and persists results to SQLite."""
        TargetAuthorizer.assert_authorized(target, project_id=project_id)

        open_ports = await PortScanner.scan_host_ports(target, ports=ports)

        with SessionLocal() as db:
            scan = NetworkScan(
                project_id=project_id,
                scan_type="tcp_port_scan",
                target=target,
                status="completed",
                summary=f"Found {len(open_ports)} open TCP ports on {target}"
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            host = Host(
                scan_id=scan.id,
                ip_address=target,
                status="up"
            )
            db.add(host)
            db.commit()
            db.refresh(host)

            for p in open_ports:
                db_port = Port(
                    host_id=host.id,
                    port_number=p["port"],
                    protocol=p["protocol"],
                    state=p["state"],
                    service_name=p["service"],
                    banner=p["banner"]
                )
                db.add(db_port)
                event_bus.emit(SecurityEventPayload(
                    event_type=EventType.PORT_DISCOVERED,
                    origin_module="BLUE",
                    category="PORT_SCAN",
                    severity="INFO",
                    description=f"Port {p['port']} ({p['service']}) open on {target}",
                    target=f"{target}:{p['port']}",
                    evidence=p
                ))
            db.commit()

        return open_ports

# Singleton Blue Recon instance
blue_recon = BlueReconnaissance()
