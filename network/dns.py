"""
GOJO INFINITY SECURITY ∞ — DNS & REVERSE DNS INTELLIGENCE
Pure Python DNS inspection compatible with Android Termux.
"""

import socket
from typing import Dict, Any, List, Optional
try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

class DNSAnalyzer:
    """Performs DNS lookups, MX, NS, TXT inspection and reverse PTR."""

    @staticmethod
    def resolve_domain(domain: str) -> Dict[str, Any]:
        """Resolves standard records (A, AAAA, MX, NS, TXT)."""
        clean_domain = domain.strip().lower()
        records: Dict[str, List[str]] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }

        # 1. Fallback via standard socket library (always works in Termux)
        try:
            addr_info = socket.getaddrinfo(clean_domain, None)
            for item in addr_info:
                ip = item[4][0]
                if ":" in ip:
                    if ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
                else:
                    if ip not in records["A"]:
                        records["A"].append(ip)
        except socket.gaierror:
            pass

        # 2. Rich record inspection via dnspython if installed
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

            for r_type in ["MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = resolver.resolve(clean_domain, r_type)
                    for rdata in answers:
                        records[r_type].append(str(rdata).strip('"'))
                except Exception:
                    pass

        return {
            "domain": clean_domain,
            "records": records,
            "resolved": len(records["A"]) > 0 or len(records["AAAA"]) > 0
        }

    @staticmethod
    def reverse_dns(ip_address: str) -> Optional[str]:
        """Performs PTR reverse lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except Exception:
            return None
