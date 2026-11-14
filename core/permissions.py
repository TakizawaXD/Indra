"""
GOJO INFINITY SECURITY ∞ — PERMISSIONS & SCOPE ENFORCEMENT
Ensures all audit, recon, and testing operations are strictly restricted
to authorized targets within registered projects.
"""

import ipaddress
from typing import Optional, Tuple
from backend.database import SessionLocal, AuthorizedTarget, Project, AuditLog
from core.logger import logger

class ScopeViolationError(PermissionError):
    """Raised when an operation targets an unauthorized IP or domain."""
    pass

class TargetAuthorizer:
    """
    Enforces authorization rules and logs all verification queries to SQLite.
    """

    ALLOWED_LOCAL_TARGETS = {
        "127.0.0.1",
        "localhost",
        "::1",
        "0.0.0.0"
    }

    @classmethod
    def is_target_authorized(
        cls,
        target: str,
        project_id: Optional[int] = None,
        operator_username: str = "system"
    ) -> Tuple[bool, str]:
        """
        Validates if target is authorized for scanning/testing.
        Returns: (is_authorized: bool, reason: str)
        """
        clean_target = target.strip().lower()

        # Localhost and local lab environments are authorized by default for testing
        if clean_target in cls.ALLOWED_LOCAL_TARGETS:
            cls._log_authorization_check(target, True, "Local loopback target automatically authorized", operator_username)
            return True, "Target is local loopback / lab range"

        with SessionLocal() as db:
            query = db.query(AuthorizedTarget)
            if project_id:
                query = query.filter(AuthorizedTarget.project_id == project_id)

            authorized_records = query.all()

            # Check exact match
            for record in authorized_records:
                reg_target = record.target.strip().lower()

                # Exact domain or IP match
                if clean_target == reg_target:
                    cls._log_authorization_check(target, True, f"Authorized under Project ID {record.project_id}", operator_username)
                    return True, f"Target explicitly authorized in Project {record.project_id}"

                # Check if target is an IP within an authorized CIDR block
                if "/" in reg_target:
                    try:
                        network = ipaddress.ip_network(reg_target, strict=False)
                        target_ip = ipaddress.ip_address(clean_target)
                        if target_ip in network:
                            cls._log_authorization_check(target, True, f"Target IP falls in CIDR {reg_target}", operator_username)
                            return True, f"Target falls within authorized CIDR block {reg_target}"
                    except ValueError:
                        pass

        cls._log_authorization_check(target, False, "Target is not present in Authorized Targets database", operator_username)
        return False, f"Target '{target}' is not registered as an authorized target in any active project."

    @classmethod
    def assert_authorized(cls, target: str, project_id: Optional[int] = None, operator: str = "system"):
        """Throws ScopeViolationError if the target is not authorized."""
        authorized, reason = cls.is_target_authorized(target, project_id, operator)
        if not authorized:
            logger.warning(f"[SECURITY ALERT] Unauthorized target access attempt blocked: {target} ({reason})")
            raise ScopeViolationError(f"Operation blocked by Infinity Scope Guard: {reason}")

    @classmethod
    def _log_authorization_check(cls, target: str, granted: bool, notes: str, operator: str):
        try:
            with SessionLocal() as db:
                audit = AuditLog(
                    action="SCOPE_AUTHORIZATION_CHECK",
                    resource=target,
                    details=f"Granted={granted} | Notes={notes} | Operator={operator}"
                )
                db.add(audit)
                db.commit()
        except Exception as e:
            logger.error(f"Failed to record authorization audit log: {e}")
