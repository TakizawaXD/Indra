"""
GOJO INFINITY SECURITY ∞ — EVENT BUS & NOTIFICATION ENGINE
Central event backbone implementing Section 12 specifications.
Connects INFINITY, BLUE, RED, PURPLE and SIX EYES asynchronously.
"""

import asyncio
import json
import uuid
from collections import deque
from datetime import datetime
from typing import Callable, Any, Optional

from core.timeutils import utcnow
from pydantic import BaseModel, Field

from core.logger import logger
from backend.database import SessionLocal, SecurityEvent

# Event Types Enumeration
class EventType:
    NETWORK_HOST_DISCOVERED = "NETWORK_HOST_DISCOVERED"
    PORT_DISCOVERED = "PORT_DISCOVERED"
    DNS_CHANGE_DETECTED = "DNS_CHANGE_DETECTED"
    IP_ANALYZED = "IP_ANALYZED"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    THREAT_DETECTED = "THREAT_DETECTED"
    THREAT_BLOCKED = "THREAT_BLOCKED"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    AUDIT_COMPLETED = "AUDIT_COMPLETED"
    DEFENSE_RULE_APPLIED = "DEFENSE_RULE_APPLIED"
    HOLLOW_PURPLE_TRIGGERED = "HOLLOW_PURPLE_TRIGGERED"
    HOLLOW_PURPLE_CONVERGENCE = "HOLLOW_PURPLE_CONVERGENCE"

class SecurityEventPayload(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    origin_module: str  # INFINITY, BLUE, RED, PURPLE, SIX_EYES
    category: str
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    source_ip: Optional[str] = None
    target: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None
    action_taken: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)

class EventBus:
    """
    Thread-safe, asynchronous event bus with SQLite persistence and WebSocket feed support.
    """
    def __init__(self):
        self._subscribers: dict[str, list[Callable[[SecurityEventPayload], Any]]] = {}
        self._global_subscribers: list[Callable[[SecurityEventPayload], Any]] = []
        self._history: deque[SecurityEventPayload] = deque(maxlen=1000)

    def subscribe(self, event_type: str, callback: Callable[[SecurityEventPayload], Any]):
        """Subscribe a handler to a specific event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable[[SecurityEventPayload], Any]):
        """Subscribe a handler to all incoming events (used by SIX EYES and WebSockets)."""
        self._global_subscribers.append(callback)

    def emit(self, event: SecurityEventPayload):
        """Synchronous dispatch helper that records and schedules listeners."""
        self._persist_to_database(event)
        self._history.append(event)

        # Notify type-specific subscribers
        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                res = handler(event)
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        asyncio.run(res)
            except Exception as e:
                logger.error(f"Error in event handler for {event.event_type}: {e}")

        # Notify global subscribers
        for g_handler in self._global_subscribers:
            try:
                res = g_handler(event)
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        asyncio.run(res)
            except Exception as e:
                logger.error(f"Error in global event handler: {e}")

    async def emit_async(self, event: SecurityEventPayload):
        """Asynchronous emitter for FastAPI / Asyncio pipelines."""
        self._persist_to_database(event)
        self._history.append(event)

        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Async error in handler for {event.event_type}: {e}")

        for g_handler in self._global_subscribers:
            try:
                if asyncio.iscoroutinefunction(g_handler):
                    await g_handler(event)
                else:
                    g_handler(event)
            except Exception as e:
                logger.error(f"Async error in global handler: {e}")

    def _persist_to_database(self, event: SecurityEventPayload):
        """Saves the event to the SQLite database permanently."""
        try:
            with SessionLocal() as session:
                db_event = SecurityEvent(
                    id=event.id,
                    event_type=event.event_type,
                    origin_module=event.origin_module,
                    category=event.category,
                    severity=event.severity,
                    description=event.description,
                    source_ip=event.source_ip,
                    target=event.target,
                    evidence_json=json.dumps(event.evidence) if event.evidence else None,
                    action_taken=event.action_taken,
                    created_at=event.created_at
                )
                session.add(db_event)
                session.commit()
        except Exception as e:
            logger.error(f"Failed to persist event {event.id} to database: {e}")

    def get_recent_events(self, limit: int = 50) -> list[SecurityEventPayload]:
        return list(self._history)[-limit:]

# Singleton Event Bus instance
event_bus = EventBus()
