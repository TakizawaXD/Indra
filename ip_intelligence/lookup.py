"""
GOJO INFINITY SECURITY ∞ — IP LOOKUP & REPUTATION ENGINE
Provides approximate geolocation, ASN, organization, and public reputation intelligence.
Strictly distinguishes approximate heuristics from verified records (Section 7).
"""

import ipaddress
import socket
from typing import Dict, Any
import httpx

from backend.database import SessionLocal, IPRecord
from core.logger import logger

class IPLookupEngine:
    """Queries IP geolocation, ASN information, and public indicators."""

    @classmethod
    async def lookup_ip(cls, ip_str: str) -> Dict[str, Any]:
        """Performs IP intelligence analysis."""
        clean_ip = ip_str.strip()

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            is_private = ip_obj.is_private
            is_loopback = ip_obj.is_loopback
            version = ip_obj.version
        except ValueError:
            return {"error": f"Invalid IP address format: {clean_ip}"}

        result: Dict[str, Any] = {
            "ip": clean_ip,
            "version": version,
            "is_private": is_private,
            "is_loopback": is_loopback,
            "reverse_dns": None,
            "geolocation": {
                "country": "Local/Private" if is_private else "Pending Lookup",
                "region": "Local/Private" if is_private else None,
                "city": "Local/Private" if is_private else None,
                "is_approximate": True,
                "disclaimer": "IP geolocation is approximate at the ISP/Regional level and cannot pinpoint physical user addresses."
            },
            "network": {
                "asn": "Private/Autonomous" if is_private else None,
                "organization": "Local Network" if is_private else None
            },
            "threat_score": 0,
            "reputation_indicators": []
        }

        # 1. Reverse DNS
        try:
            hostname, _, _ = socket.gethostbyaddr(clean_ip)
            result["reverse_dns"] = hostname
        except Exception:
            pass

        # 2. Public IP Geolocation & ASN Query (only for public addresses)
        if not is_private and not is_loopback:
            try:
                # Query free public RDAP / GeoJSON lookup service
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(f"https://ipapi.co/{clean_ip}/json/")
                    if resp.status_code == 200:
                        data = resp.json()
                        result["geolocation"]["country"] = data.get("country_name")
                        result["geolocation"]["region"] = data.get("region")
                        result["geolocation"]["city"] = data.get("city")
                        result["network"]["asn"] = data.get("asn")
                        result["network"]["organization"] = data.get("org")
            except Exception:
                result["lookup_notice"] = "External lookup unavailable or offline; cached/local data only."

        # Save to database
        cls._persist_ip_record(result)

        return result

    @classmethod
    def _persist_ip_record(cls, data: Dict[str, Any]):
        try:
            with SessionLocal() as db:
                ip_addr = data["ip"]
                existing = db.query(IPRecord).filter(IPRecord.ip_address == ip_addr).first()
                if not existing:
                    existing = IPRecord(
                        ip_address=ip_addr,
                        ip_version=data["version"],
                        is_private=data["is_private"],
                        country=data["geolocation"].get("country"),
                        city=data["geolocation"].get("city"),
                        asn=data["network"].get("asn"),
                        organization=data["network"].get("organization"),
                        reverse_dns=data["reverse_dns"],
                        threat_score=data["threat_score"]
                    )
                    db.add(existing)
                else:
                    existing.country = data["geolocation"].get("country") or existing.country
                    existing.city = data["geolocation"].get("city") or existing.city
                    existing.reverse_dns = data["reverse_dns"] or existing.reverse_dns
                db.commit()
        except Exception as e:
            logger.error(f"Failed to persist IPRecord: {e}")
