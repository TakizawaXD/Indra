"""
GOJO INFINITY SECURITY ∞ — TCP PORT SCANNER & SERVICE DETECTOR
Asynchronous, non-root TCP Connect scanner optimized for Termux.
"""

import asyncio
from typing import List, Dict, Any, Optional

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017
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
                "banner": banner[:128] if banner else None
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
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
