"""
GOJO INFINITY SECURITY ∞ — CONSENT-BASED IP LOGGER & VISIT RECORDER
Provides transparent visit auditing on user-administered services.
Respects user privacy and consent policies (Section 7).
"""

import csv
import io
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from backend.database import SessionLocal, IPRecord, IPHistory
from core.logger import logger
from core.event_engine import event_bus, EventType, SecurityEventPayload

class IPLoggerService:
    """Manages visit auditing, history tracking, CSV exports, and retention."""

    @classmethod
    def record_visit(
        cls,
        ip_address: str,
        path: str,
        user_agent: Optional[str] = None,
        consent_status: str = "informed_service_visit"
    ) -> Dict[str, Any]:
        """Records an informed visit to a managed service endpoint."""
        with SessionLocal() as db:
            record = db.query(IPRecord).filter(IPRecord.ip_address == ip_address).first()
            if not record:
                is_private = ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address == "127.0.0.1"
                record = IPRecord(
                    ip_address=ip_address,
                    is_private=is_private,
                    last_seen=datetime.utcnow()
                )
                db.add(record)
                db.commit()
                db.refresh(record)
            else:
                record.last_seen = datetime.utcnow()

            history_entry = IPHistory(
                ip_id=record.id,
                event_type="logger_visit",
                path_accessed=path,
                user_agent=user_agent[:250] if user_agent else None,
                consent_status=consent_status
            )
            db.add(history_entry)
            db.commit()

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.IP_ANALYZED,
            origin_module="IP_INTEL",
            category="VISIT_LOGGER",
            severity="INFO",
            description=f"Informed visit logged from {ip_address} accessing {path}",
            source_ip=ip_address,
            target=path
        ))

        return {
            "ip": ip_address,
            "path": path,
            "recorded_at": datetime.utcnow().isoformat(),
            "consent_status": consent_status
        }

    @classmethod
    def get_visit_history(cls, limit: int = 100, ip_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Queries logged visits with optional IP filtering."""
        with SessionLocal() as db:
            query = db.query(IPHistory, IPRecord).join(IPRecord, IPHistory.ip_id == IPRecord.id)
            if ip_filter:
                query = query.filter(IPRecord.ip_address == ip_filter)

            results = query.order_by(IPHistory.recorded_at.desc()).limit(limit).all()

            return [
                {
                    "id": h.id,
                    "ip": r.ip_address,
                    "path": h.path_accessed,
                    "user_agent": h.user_agent,
                    "consent": h.consent_status,
                    "country": r.country,
                    "timestamp": h.recorded_at.isoformat()
                }
                for h, r in results
            ]

    @classmethod
    def export_csv(cls) -> str:
        """Exports all visit records to CSV format."""
        history = cls.get_visit_history(limit=1000)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "IP", "Path", "User-Agent", "Consent Status", "Country", "Timestamp"])

        for row in history:
            writer.writerow([
                row["id"],
                row["ip"],
                row["path"],
                row["user_agent"],
                row["consent"],
                row["country"],
                row["timestamp"]
            ])

        return output.getvalue()

    @classmethod
    def prune_retention(cls, days: int = 30) -> int:
        """Enforces privacy retention by deleting records older than N days."""
        threshold = datetime.utcnow() - timedelta(days=days)
        with SessionLocal() as db:
            deleted = db.query(IPHistory).filter(IPHistory.recorded_at < threshold).delete()
            db.commit()
            logger.info(f"[IP LOGGER] Retention policy pruned {deleted} records older than {days} days.")
            return deleted
