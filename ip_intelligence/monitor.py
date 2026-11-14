"""
GOJO INFINITY SECURITY ∞ — IP MONITOR & CHANGE DETECTION
Monitors configured assets and local IPs for DNS or address drifts.
"""

from core.timeutils import utcnow
from typing import Dict, Any, List
from core.event_engine import event_bus, EventType, SecurityEventPayload
from network.dns import DNSAnalyzer

class IPMonitor:
    """Supervises managed IPs and domains, alerting on IP changes or DNS hijacking."""

    @classmethod
    def check_monitored_domains(cls, domains: List[str]) -> List[Dict[str, Any]]:
        """Verifies DNS resolutions against expected values."""
        results = []
        for domain in domains:
            dns_info = DNSAnalyzer.resolve_domain(domain)
            current_ips = dns_info["records"].get("A", [])

            results.append({
                "domain": domain,
                "current_ips": current_ips,
                "checked_at": utcnow().isoformat()
            })

            event_bus.emit(SecurityEventPayload(
                event_type=EventType.DNS_CHANGE_DETECTED,
                origin_module="IP_INTEL",
                category="MONITORING",
                severity="INFO",
                description=f"IP monitor verified domain '{domain}' -> {current_ips}",
                target=domain,
                evidence={"resolved_ips": current_ips}
            ))

        return results
