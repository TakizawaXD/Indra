"""
GOJO INFINITY SECURITY ∞ — TCP PORT SCANNER & SERVICE DETECTOR
Asynchronous, non-root TCP Connect scanner optimized for Termux.
"""

import asyncio
import re
from typing import List, Dict, Any, Optional

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017
]

# Expanded "top ports" sweep for a deeper authorized recon pass.
TOP_PORTS = sorted(set(COMMON_PORTS + [
    7, 20, 26, 69, 79, 81, 88, 111, 123, 135, 137, 139, 161, 389, 427, 465,
    514, 515, 548, 554, 587, 623, 636, 873, 902, 989, 990, 1025, 1026, 1080,
    1099, 1194, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
    2375, 2376, 2404, 3000, 3128, 3260, 3690, 4000, 4040, 4444, 4567, 4848,
    5000, 5001, 5060, 5061, 5222, 5353, 5555, 5601, 5672, 5984, 5985, 5986,
    6000, 6443, 6667, 7001, 7077, 7199, 7474, 7687, 8001, 8008, 8086, 8088,
    8089, 8090, 8161, 8333, 8444, 8500, 8787, 8888, 9001, 9042, 9090, 9092,
    9100, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 25565, 27018, 50070,
]))

# Ports whose exposure to untrusted networks is high-risk (admin/data planes).
RISKY_PORTS = {
    21, 23, 25, 111, 135, 137, 139, 445, 512, 513, 514, 1433, 1521, 2049,
    2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 7001, 8020, 9042, 9200,
    11211, 27017, 27018, 50070,
}

# Lightweight banner -> version extraction patterns.
_VERSION_PATTERNS = [
    re.compile(r"SSH-[\d.]+-([^\r\n]+)", re.IGNORECASE),
    re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),
    re.compile(r"\b(nginx|apache|microsoft-iis|openssh|mysql|mariadb|postgresql|redis|mongodb|vsftpd|proftpd|exim|postfix)[/ ]?([\d.]+)?", re.IGNORECASE),
]

SERVICE_SIGNATURES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt (Gojo)",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "SonarQube/PHP-FPM",
    27017: "MongoDB"
}

class PortScanner:
    """Non-blocking TCP Connect Port Scanner."""

    @staticmethod
    async def probe_port(host: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Probes a single TCP port and grabs banner if possible."""
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            service_guess = SERVICE_SIGNATURES.get(port, "unknown")
            banner = ""

            # Attempt non-invasive banner grab
            try:
                # Send HTTP HEAD probe if HTTP/HTTPS, or read immediate greeting for SSH/FTP
                if port in (80, 8080, 8000):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                elif port in (21, 22):
                    pass # wait for daemon greeting

                banner_data = await asyncio.wait_for(reader.read(256), timeout=0.8)
                banner = banner_data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service_guess,
                "banner": banner[:128] if banner else None,
                "version": PortScanner.extract_version(banner),
                "risk": "HIGH" if port in RISKY_PORTS else "INFO",
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    @staticmethod
    def extract_version(banner: str) -> Optional[str]:
        """Best-effort software/version fingerprint from a service banner."""
        if not banner:
            return None
        for pat in _VERSION_PATTERNS:
            m = pat.search(banner)
            if m:
                return " ".join(g for g in m.groups() if g).strip()[:64] or None
        return None

    @classmethod
    async def scan_host_ports(
        cls,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 1.2,
        concurrency: int = 32
    ) -> List[Dict[str, Any]]:
        """Scans a host for open ports within concurrency limits."""
        target_ports = ports or COMMON_PORTS
        semaphore = asyncio.Semaphore(concurrency)

        async def worker(p: int):
            async with semaphore:
                return await cls.probe_port(host, p, timeout)

        tasks = [worker(p) for p in target_ports]
        results = await asyncio.gather(*tasks)
        open_ports = [r for r in results if r is not None]
        open_ports.sort(key=lambda x: x["port"])
        return open_ports
