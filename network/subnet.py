"""
GOJO INFINITY SECURITY ∞ — SUBNET & CIDR CALCULATOR
Provides network math, address parsing, IP range generation, and subnetwork partitioning.
"""

import ipaddress
from typing import Dict, Any, List

class SubnetCalculator:
    """Calculates network masks, broadcast addresses, usable hosts, and CIDR blocks."""

    @staticmethod
    def calculate_cidr(cidr_str: str) -> Dict[str, Any]:
        """Parses CIDR notation and returns detailed network metrics."""
        try:
            network = ipaddress.ip_network(cidr_str.strip(), strict=False)
            num_addresses = network.num_addresses
            usable_hosts = max(0, num_addresses - 2) if network.version == 4 and network.prefixlen < 31 else num_addresses

            first_host = str(network.network_address + 1) if usable_hosts > 0 else str(network.network_address)
            last_host = str(network.broadcast_address - 1) if usable_hosts > 0 else str(network.broadcast_address)

            return {
                "input": cidr_str,
                "version": network.version,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address) if network.version == 4 else None,
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "prefix_length": network.prefixlen,
                "total_addresses": num_addresses,
                "usable_hosts": usable_hosts,
                "first_host": first_host,
                "last_host": last_host,
                "is_private": network.is_private,
                "is_loopback": network.is_loopback
            }
        except ValueError as e:
            return {"error": f"Invalid CIDR notation: {e}"}

    @staticmethod
    def get_host_list(cidr_str: str, max_hosts: int = 256) -> List[str]:
        """Generates list of host IPs up to max_hosts."""
        try:
            network = ipaddress.ip_network(cidr_str.strip(), strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            return hosts[:max_hosts]
        except Exception:
            return []
