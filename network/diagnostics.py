"""
GOJO INFINITY SECURITY ∞ — NETWORK DIAGNOSTICS & INTERFACE ENGINE
Inspects local network interfaces, gateways, routing reachability, and public IP resolution.
"""

import socket
from typing import Dict, Any, List
import httpx

try:
    import psutil
except ImportError:
    psutil = None

class NetworkDiagnostics:
    """Diagnoses connectivity, network interfaces, and IP configurations."""

    @staticmethod
    def get_local_interfaces() -> List[Dict[str, Any]]:
        """Inspects all network interfaces available on the Android/Linux device."""
        if psutil:
            try:
                interfaces = []
                net_if_addrs = psutil.net_if_addrs()
                net_if_stats = psutil.net_if_stats()

                for name, addrs in net_if_addrs.items():
                    stats = net_if_stats.get(name)
                    iface_info = {
                        "interface": name,
                        "is_up": stats.isup if stats else False,
                        "speed_mbps": stats.speed if stats else 0,
                        "ipv4": [],
                        "ipv6": [],
                        "mac": None
                    }
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            iface_info["ipv4"].append({
                                "address": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": addr.broadcast
                            })
                        elif addr.family == socket.AF_INET6:
                            iface_info["ipv6"].append(addr.address)
                        elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                            iface_info["mac"] = addr.address

                    interfaces.append(iface_info)
                return interfaces
            except Exception:
                pass

        # Fallback for Android Termux without psutil
        fallback_ip = "127.0.0.1"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                fallback_ip = s.getsockname()[0]
        except Exception:
            pass
        return [{
            "interface": "wlan0/eth0",
            "is_up": True,
            "speed_mbps": 0,
            "ipv4": [{"address": fallback_ip, "netmask": "255.255.255.0", "broadcast": None}],
            "ipv6": [],
            "mac": None
        }]

    @staticmethod
    def get_device_ip_overview() -> Dict[str, Any]:
        """Discovers primary local IP and attempts public IP lookup."""
        local_ip = "127.0.0.1"
        try:
            # Trick to get outbound interface without actually sending traffic
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except Exception:
            pass

        return {
            "primary_local_ip": local_ip,
            "interfaces": NetworkDiagnostics.get_local_interfaces()
        }

    @staticmethod
    async def fetch_public_ip_info() -> Dict[str, Any]:
        """Resolves public IP via safe external lookup when Internet is accessible."""
        providers = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/all.json"
        ]
        for url in providers:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return resp.json() if "json" in resp.headers.get("content-type", "") else {"ip": resp.text.strip()}
            except Exception:
                continue

        return {"ip": "Offline or Unreachable", "status": "no_external_internet"}
