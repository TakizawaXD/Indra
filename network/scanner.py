"""
GOJO INFINITY SECURITY ∞ — HOST DISCOVERY & NETWORK SCANNER
Discovers active hosts within authorized network ranges without requiring root.
"""

import asyncio
import socket
import subprocess
import time
from typing import List, Dict, Any, Optional

from core.logger import logger
from core.permissions import TargetAuthorizer
from core.event_engine import event_bus, EventType, SecurityEventPayload
from network.subnet import SubnetCalculator
from backend.database import SessionLocal, Host, NetworkScan

class NetworkScanner:
    """Discovers alive hosts and maps reachable endpoints in authorized scopes."""

    PROBE_PORTS = [80, 443, 22, 53, 8080]

    @classmethod
    async def is_host_alive(cls, ip: str, timeout: float = 0.8) -> Tuple_Result := tuple[bool, Optional[float]]:
        """Tests if host is reachable via fast TCP connect probes on standard ports."""
        t_start = time.time()
        for port in cls.PROBE_PORTS:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                rtt = round((time.time() - t_start) * 1000, 2)
                return True, rtt
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

        # Fallback to local ping command if available
        try:
            res = await asyncio.to_thread(
                subprocess.run,
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5
            )
            if res.returncode == 0:
                return True, round((time.time() - t_start) * 1000, 2)
        except Exception:
            pass

        return False, None

    @classmethod
    async def discover_subnet(
        cls,
        cidr: str,
        project_id: Optional[int] = None,
        concurrency: int = 24
    ) -> List[Dict[str, Any]]:
        """Scans authorized CIDR block for responsive hosts."""
        # Enforce scope check
        TargetAuthorizer.assert_authorized(cidr, project_id=project_id)

        hosts = SubnetCalculator.get_host_list(cidr, max_hosts=128)
        semaphore = asyncio.Semaphore(concurrency)
        discovered_hosts: List[Dict[str, Any]] = []

        logger.info(f"[BLUE RECON] Initiating host discovery over authorized scope {cidr} ({len(hosts)} targets)...")

        async def worker(ip: str):
            async with semaphore:
                alive, rtt = await cls.is_host_alive(ip)
                if alive:
                    host_info = {
                        "ip": ip,
                        "status": "up",
                        "response_time_ms": rtt
                    }
                    discovered_hosts.append(host_info)
                    event_bus.emit(SecurityEventPayload(
                        event_type=EventType.NETWORK_HOST_DISCOVERED,
                        origin_module="BLUE",
                        category="HOST_DISCOVERY",
                        severity="INFO",
                        description=f"Host discovered online: {ip} (RTT: {rtt}ms)",
                        target=ip,
                        evidence={"rtt_ms": rtt}
                    ))

        tasks = [worker(ip) for ip in hosts]
        await asyncio.gather(*tasks)

        # Persist discovered hosts to DB
        with SessionLocal() as db:
            scan = NetworkScan(
                project_id=project_id,
                scan_type="host_discovery",
                target=cidr,
                status="completed",
                summary=f"Found {len(discovered_hosts)} active hosts in {cidr}"
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            for h in discovered_hosts:
                db_host = Host(
                    scan_id=scan.id,
                    ip_address=h["ip"],
                    status="up",
                    response_time_ms=h["response_time_ms"]
                )
                db.add(db_host)
            db.commit()

        logger.info(f"[BLUE RECON] Discovery complete. Found {len(discovered_hosts)} active hosts.")
        return discovered_hosts
