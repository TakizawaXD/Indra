"""
GOJO INFINITY SECURITY ∞ — INFINITY SHIELD (DEFENSE ENGINE)
Implements Layered Application Defense (Infinity Concept):
"The closer an attack gets, the slower and more impossible its traversal becomes."
Color Motif: Electric Blue & Cyan
"""

import time
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

from core.logger import logger
from core.event_engine import event_bus, EventType, SecurityEventPayload
from backend.database import SessionLocal, FirewallRule, SecurityEvent, Threat

class TokenBucketRateLimiter:
    """In-memory high-speed sliding rate limiter per IP address."""
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        now = time.time()
        timestamps = self.requests[client_ip]
        # Prune old timestamps
        while timestamps and timestamps[0] <= now - self.window_seconds:
            timestamps.pop(0)

        if len(timestamps) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - timestamps[0]))
            return False, max(1, retry_after)

        timestamps.append(now)
        return True, 0

class InfinityShield:
    """
    Multilayer application firewall, rate limiter, and intrusion prevention engine.
    Filters traffic on services managed by Gojo Infinity.
    """

    # Signatures for malicious application traffic
    INSPECTION_RULES = [
        (re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\bunion\b)|(\bselect\b.*\bfrom\b)", re.IGNORECASE), "SQL_INJECTION_PROBE", "HIGH"),
        (re.compile(r"(<script.*?>)|(javascript:)|(onerror=)|(\balert\(.*?\))", re.IGNORECASE), "XSS_PAYLOAD_DETECTED", "MEDIUM"),
        (re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/)", re.IGNORECASE), "DIRECTORY_TRAVERSAL_ATTEMPT", "HIGH"),
        (re.compile(r"(\bcmd\.exe\b|\/bin\/sh|\/bin\/bash|\bwhoami\b|\bcat\s+/etc/passwd)", re.IGNORECASE), "COMMAND_INJECTION_PROBE", "CRITICAL"),
        (re.compile(r"(\.env|\.git\/config|wp-config\.php|\.htaccess)", re.IGNORECASE), "SENSITIVE_FILE_PROBING", "MEDIUM")
    ]

    def __init__(self):
        self.limiter = TokenBucketRateLimiter(max_requests=120, window_seconds=60)
        self.failed_attempts: Dict[str, int] = defaultdict(int)
        self.total_inspections: int = 0
        self.total_blocked: int = 0

    def inspect_request(
        self,
        client_ip: str,
        path: str,
        method: str,
        query_string: str = "",
        body_sample: str = "",
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Runs multi-layer inspection on incoming HTTP traffic.
        Returns: (is_allowed: bool, reason: str, block_type: str)
        """
        self.total_inspections += 1

        # LAYER 1: Active IP Ban Verification (Database rule lookup)
        if self.is_ip_banned(client_ip):
            self.total_blocked += 1
            event_bus.emit(SecurityEventPayload(
                event_type=EventType.THREAT_BLOCKED,
                origin_module="INFINITY",
                category="IP_BAN",
                severity="HIGH",
                description=f"Infinity Shield blocked blacklisted IP: {client_ip}",
                source_ip=client_ip,
                target=path,
                action_taken="DENY_403"
            ))
            return False, "Access denied by Infinity Shield IP filter rule", "IP_BAN"

        # LAYER 2: Rate Limiting
        allowed, retry_after = self.limiter.is_allowed(client_ip)
        if not allowed:
            self.total_blocked += 1
            event_bus.emit(SecurityEventPayload(
                event_type=EventType.THREAT_BLOCKED,
                origin_module="INFINITY",
                category="RATE_LIMIT",
                severity="MEDIUM",
                description=f"Rate limit exceeded by {client_ip}. Retry after {retry_after}s",
                source_ip=client_ip,
                target=path,
                action_taken="RATE_LIMIT_429"
            ))
            return False, f"Too Many Requests. Infinity Shield rate limit in effect (Retry in {retry_after}s)", "RATE_LIMIT"

        # LAYER 3: Payload & URL Traversal Inspection
        target_payload = f"{path}?{query_string} {body_sample}"
        for pattern, attack_type, severity in self.INSPECTION_RULES:
            if pattern.search(target_payload):
                self.total_blocked += 1
                self._record_threat(client_ip, attack_type, severity, target_payload)

                event_bus.emit(SecurityEventPayload(
                    event_type=EventType.THREAT_BLOCKED,
                    origin_module="INFINITY",
                    category=attack_type,
                    severity=severity,
                    description=f"Infinity Shield neutralized {attack_type} from {client_ip} targeting {path}",
                    source_ip=client_ip,
                    target=path,
                    evidence={"payload": target_payload[:256]},
                    action_taken="PAYLOAD_FILTER_403"
                ))

                # Increment suspicious attempts and ban if threshold reached
                self.failed_attempts[client_ip] += 1
                if self.failed_attempts[client_ip] >= 5:
                    self.ban_ip(client_ip, reason=f"Repeated {attack_type} attempts", duration_minutes=30)

                return False, f"Blocked by Infinity Shield: Malicious signature identified ({attack_type})", attack_type

        return True, None, None

    def is_ip_banned(self, ip_address: str) -> bool:
        """Checks if IP is currently under active ban."""
        now = datetime.utcnow()
        with SessionLocal() as db:
            active_rule = db.query(FirewallRule).filter(
                FirewallRule.target_pattern == ip_address,
                FirewallRule.rule_type == "IP_BAN",
                FirewallRule.is_active == True
            ).first()

            if active_rule:
                if active_rule.expires_at and active_rule.expires_at < now:
                    active_rule.is_active = False
                    db.commit()
                    return False
                active_rule.hits += 1
                db.commit()
                return True
        return False

    def ban_ip(self, ip_address: str, reason: str = "Manual operator ban", duration_minutes: int = 60) -> FirewallRule:
        """Adds an IP to the active Infinity Shield blocklist."""
        expires = datetime.utcnow() + timedelta(minutes=duration_minutes) if duration_minutes > 0 else None
        with SessionLocal() as db:
            existing = db.query(FirewallRule).filter(
                FirewallRule.target_pattern == ip_address,
                FirewallRule.rule_type == "IP_BAN"
            ).first()

            if existing:
                existing.is_active = True
                existing.expires_at = expires
                rule = existing
            else:
                rule = FirewallRule(
                    rule_name=f"BAN_{ip_address}_{int(time.time())}",
                    rule_type="IP_BAN",
                    target_pattern=ip_address,
                    action="DENY",
                    is_active=True,
                    expires_at=expires
                )
                db.add(rule)
            db.commit()

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.DEFENSE_RULE_APPLIED,
            origin_module="INFINITY",
            category="IP_BAN",
            severity="HIGH",
            description=f"Infinity Shield banned IP {ip_address} for {duration_minutes}m. Reason: {reason}",
            source_ip=ip_address,
            action_taken="IP_BAN_ENFORCED"
        ))
        logger.warning(f"[INFINITY SHIELD] IP {ip_address} banned for {duration_minutes}m ({reason})")
        return rule

    def unban_ip(self, ip_address: str) -> bool:
        """Removes an IP ban."""
        with SessionLocal() as db:
            rule = db.query(FirewallRule).filter(
                FirewallRule.target_pattern == ip_address,
                FirewallRule.rule_type == "IP_BAN"
            ).first()
            if rule:
                rule.is_active = False
                db.commit()
                logger.info(f"[INFINITY SHIELD] Unbanned IP: {ip_address}")
                return True
        return False

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Lists active firewall rules."""
        with SessionLocal() as db:
            rules = db.query(FirewallRule).filter(FirewallRule.is_active == True).all()
            return [
                {
                    "id": r.id,
                    "name": r.rule_name,
                    "type": r.rule_type,
                    "target": r.target_pattern,
                    "action": r.action,
                    "hits": r.hits,
                    "created_at": r.created_at.isoformat(),
                    "expires_at": r.expires_at.isoformat() if r.expires_at else "Permanent"
                }
                for r in rules
            ]

    def _record_threat(self, ip: str, threat_type: str, severity: str, sample: str):
        try:
            with SessionLocal() as db:
                threat = Threat(
                    threat_type=threat_type,
                    source_ip=ip,
                    severity=severity,
                    status="mitigated",
                    mitigation_applied="Infinity Shield payload filter drop"
                )
                db.add(threat)
                db.commit()
        except Exception as e:
            logger.error(f"Error persisting threat record: {e}")

# Global Infinity Shield Instance
infinity_shield = InfinityShield()
