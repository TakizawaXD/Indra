"""
GOJO INFINITY SECURITY ∞ — CORE RUNTIME ENGINE
Manages system lifecycle, module states, uptime and system telemetry.
"""

import time
from core.timeutils import utcnow
import os
import psutil
from typing import Dict, Any

from core.config import settings
from core.logger import logger
from backend.database import init_db

class SystemState:
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"

class GojoEngine:
    """
    Central operational engine for Gojo Infinity Security.
    Controls the subsystem status, resource monitors and Termux health.
    """

    def __init__(self):
        self.state = SystemState.STOPPED
        self.start_time: float = 0.0
        self.modules: Dict[str, str] = {
            "infinity_shield": "INITIALIZING",
            "blue_recon": "INITIALIZING",
            "red_operations": "INITIALIZING",
            "purple_intelligence": "INITIALIZING",
            "six_eyes_brain": "INITIALIZING",
            "network_intelligence": "INITIALIZING",
            "ip_intelligence": "INITIALIZING",
            "vulnerability_center": "INITIALIZING",
            "attack_lab": "INITIALIZING"
        }

    def startup(self) -> bool:
        """Initializes the database and wakes all subsystems."""
        from core.license import IndraLicenseGuard
        if not IndraLicenseGuard.verify_license():
            logger.warning("[LICENSE] Sistema iniciado en modo BLOQUEADO. Esperando: 'insertar llave'")
            self.state = SystemState.DEGRADED
            return False

        logger.info(f"Awakening {settings.APP_NAME}...")
        self.state = SystemState.STARTING
        self.start_time = time.time()

        # Step 1: Initialize Database
        init_db()

        # Step 2: Set module statuses to ONLINE
        for mod in self.modules:
            self.modules[mod] = "ONLINE"

        self.state = SystemState.ONLINE
        return True
        logger.info(f"{settings.APP_NAME} is fully ONLINE and operational.")

    def shutdown(self):
        """Gracefully halts all internal active routines."""
        logger.info("Gracefully decommissioning Gojo Infinity subsystems...")
        for mod in self.modules:
            self.modules[mod] = "STOPPED"
        self.state = SystemState.STOPPED
        logger.info("Infinity system halted safely.")

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns real-time resource and runtime stats."""
        uptime = time.time() - self.start_time if self.start_time > 0 else 0
        memory_usage_mb = 0
        cpu_percent = 0.0

        try:
            process = psutil.Process(os.getpid())
            mem_info = process.memory_info()
            memory_usage_mb = round(mem_info.rss / (1024 * 1024), 2)
            cpu_percent = process.cpu_percent(interval=None)
        except Exception:
            pass

        return {
            "system": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": self.state,
            "uptime_seconds": round(uptime, 1),
            "memory_usage_mb": memory_usage_mb,
            "cpu_percent": cpu_percent,
            "modules": self.modules,
            "timestamp": utcnow().isoformat()
        }

# Global Engine instance
engine_runtime = GojoEngine()
