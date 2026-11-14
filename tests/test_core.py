"""
Unit tests for Core Subsystem: Database, Event Bus, Permissions, Orchestrator.
"""

import unittest
from backend.database import init_db, SessionLocal, Project, AuthorizedTarget, SecurityEvent
from core.event_engine import event_bus, EventType, SecurityEventPayload
from core.permissions import TargetAuthorizer, ScopeViolationError
from core.orchestrator import six_eyes
from core.engine import engine_runtime

class TestGojoCore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_database_initialization(self):
        with SessionLocal() as db:
            # Check we can create and retrieve a project
            proj = Project(name="Project_Test_Alpha", description="Unit Test Scope")
            db.add(proj)
            db.commit()
            db.refresh(proj)

            self.assertIsNotNone(proj.id)
            self.assertEqual(proj.name, "Project_Test_Alpha")

            # Clean up
            db.delete(proj)
            db.commit()

    def test_permissions_scope_authorization(self):
        # 1. Localhost should be authorized by default
        auth, reason = TargetAuthorizer.is_target_authorized("127.0.0.1")
        self.assertTrue(auth)

        # 2. Random unauthorized IP should be rejected
        unauth_ip = "198.51.100.44"
        auth, reason = TargetAuthorizer.is_target_authorized(unauth_ip)
        self.assertFalse(auth)

        # 3. Add to authorized target and check again
        with SessionLocal() as db:
            proj = Project(name="Project_Target_Test", description="CIDR Test")
            db.add(proj)
            db.commit()
            db.refresh(proj)

            target = AuthorizedTarget(
                project_id=proj.id,
                target="198.51.100.0/24",
                target_type="cidr",
                authorization_notes="Unit Test Lab Range"
            )
            db.add(target)
            db.commit()

            auth_in_cidr, _ = TargetAuthorizer.is_target_authorized(unauth_ip)
            self.assertTrue(auth_in_cidr)

            # Clean up
            db.delete(target)
            db.delete(proj)
            db.commit()

    def test_event_bus_and_persistence(self):
        received_events = []

        def handler(event: SecurityEventPayload):
            received_events.append(event)

        event_bus.subscribe(EventType.THREAT_DETECTED, handler)

        test_payload = SecurityEventPayload(
            event_type=EventType.THREAT_DETECTED,
            origin_module="SIX_EYES",
            category="TEST",
            severity="HIGH",
            description="Unit Test Threat Event",
            source_ip="10.0.0.99"
        )
        event_bus.emit(test_payload)

        self.assertGreaterEqual(len(received_events), 1)
        self.assertEqual(received_events[-1].description, "Unit Test Threat Event")

    def test_gojo_ai_offline_knowledge(self):
        res = six_eyes.ai.ask("Explain SQL Injection risk")
        self.assertIn("SQL Injection", res["answer"])
        self.assertEqual(res["source"], "six_eyes_offline_knowledge")

if __name__ == "__main__":
    unittest.main()
