"""
GOJO INFINITY SECURITY ∞ — TERMUX NOTIFICATION ENGINE
Dispatches native Android notifications via termux-notification when critical threats are neutralized.
Designed for Indra | Architect: Takizawa
"""

import shutil
import subprocess
from core.logger import logger
from core.event_engine import event_bus, EventType, SecurityEventPayload

class TermuxNotifier:
    """Sends native Android push alerts through Termux API if present."""

    HAS_TERMUX_NOTIFY = shutil.which("termux-notification") is not None

    @classmethod
    def send_notification(
        cls,
        title: str,
        content: str,
        priority: str = "high",
        vibrate: bool = True
    ) -> bool:
        """Triggers native Android notification via termux-notification CLI."""
        if not cls.HAS_TERMUX_NOTIFY:
            # Silently fallback to structured logger if termux-api CLI is not installed
            logger.debug(f"[NOTIFIER (Terminal Fallback)] {title} - {content}")
            return False

        try:
            cmd = [
                "termux-notification",
                "--title", f"∞ INDRA | {title}",
                "--content", content,
                "--priority", priority,
                "--id", "gojo_threat_alert"
            ]
            if vibrate:
                cmd.extend(["--vibrate", "500,250,500"])

            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            return True
        except Exception as e:
            logger.debug(f"Failed to dispatch Termux notification: {e}")
            return False

    @classmethod
    def setup_listeners(cls):
        """Attaches notification dispatcher to the Event Bus for critical events."""
        event_bus.subscribe(EventType.THREAT_BLOCKED, cls._on_threat_blocked)
        event_bus.subscribe(EventType.HOLLOW_PURPLE_CONVERGENCE, cls._on_hollow_purple_done)

    @classmethod
    def _on_threat_blocked(cls, event: SecurityEventPayload):
        if event.severity in ["HIGH", "CRITICAL"]:
            cls.send_notification(
                title=f"Amenaza Neutralizada ({event.category})",
                content=f"Infinity Shield bloqueó al atacante: {event.source_ip or 'Desconocido'}",
                priority="high"
            )

    @classmethod
    def _on_hollow_purple_done(cls, event: SecurityEventPayload):
        cls.send_notification(
            title="Hollow Purple Completado",
            content=f"Convergencia finalizada en {event.target}. Postura de seguridad verificada.",
            priority="default"
        )

# Initialize listeners
TermuxNotifier.setup_listeners()

