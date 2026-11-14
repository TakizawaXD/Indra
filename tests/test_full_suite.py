"""
GOJO INFINITY SECURITY ∞ — COMPREHENSIVE AUTOMATED TEST SUITE
Tests all subsystems: Database, Event Bus, Infinity Shield, Blue Recon,
Red Operations, Purple Intel, IP Intelligence, Attack Lab, API Endpoints, Reports.
"""

import unittest
import asyncio
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import init_db, SessionLocal, Project, AuthorizedTarget, FirewallRule
from core.event_engine import event_bus, EventType, SecurityEventPayload
from core.permissions import TargetAuthorizer
from techniques.infinity.shield import infinity_shield
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from techniques.purple.quarantine import quarantine_vault
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from laboratory.web_lab import AttackLabSimulator
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer

class TestGojoComprehensiveSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    # 1. INFINITY SHIELD TESTS
    def test_infinity_shield_waf_inspection(self):
        # Clean request
        allowed, reason, block = infinity_shield.inspect_request(
            client_ip="192.168.1.50",
            path="/api/telemetry",
            method="GET"
        )
        self.assertTrue(allowed)

        # SQL Injection attempt probe
        allowed, reason, block = infinity_shield.inspect_request(
            client_ip="192.168.1.51",
            path="/api/search",
            method="GET",
            query_string="query=1%27%20OR%201=1--"
        )
        self.assertFalse(allowed)
        self.assertIn("SQL", block)

        # Directory traversal attempt
        allowed, reason, block = infinity_shield.inspect_request(
            client_ip="192.168.1.52",
            path="/api/download",
            method="GET",
            query_string="file=../../../../etc/passwd"
        )
        self.assertFalse(allowed)

    def test_infinity_shield_ip_ban(self):
        test_ip = "203.0.113.88"
        infinity_shield.ban_ip(test_ip, reason="Test Ban", duration_minutes=10)
        self.assertTrue(infinity_shield.is_ip_banned(test_ip))

        # Request from banned IP should be blocked
        allowed, _, block = infinity_shield.inspect_request(test_ip, "/test", "GET")
        self.assertFalse(allowed)
        self.assertEqual(block, "IP_BAN")

        # Unban
        infinity_shield.unban_ip(test_ip)
        self.assertFalse(infinity_shield.is_ip_banned(test_ip))

    # 2. RED AUDITING TESTS
    def test_red_password_entropy(self):
        weak_res = red_operations.audit_password_strength("123456")
        self.assertEqual(weak_res["strength"], "VERY_WEAK")
        self.assertFalse(weak_res["is_acceptable_for_admin"])

        strong_res = red_operations.audit_password_strength("Satoru#Gojo!Limitless2026$Infinity")
        self.assertEqual(strong_res["strength"], "VERY_STRONG")
        self.assertTrue(strong_res["is_acceptable_for_admin"])

    # 3. PURPLE CORRELATION & REPORTS
    def test_purple_risk_and_report(self):
        risk = purple_intel.calculate_risk_index()
        self.assertIn("risk_index", risk)
        self.assertIn("risk_level", risk)

        report = purple_intel.generate_unified_security_report(project_name="Unit_Test_Purple")
        self.assertIn("report_title", report)
        self.assertTrue(len(report["report_path"]) > 0)

    # 4. IP INTELLIGENCE & CONSENT LOGGER
    def test_ip_lookup_and_logger(self):
        # Lookup loopback
        res = asyncio.run(IPLookupEngine.lookup_ip("127.0.0.1"))
        self.assertTrue(res["is_loopback"])
        self.assertEqual(res["ip"], "127.0.0.1")

        # Record visit
        visit = IPLoggerService.record_visit("127.0.0.1", "/api/dashboard", user_agent="PyTest/1.0")
        self.assertEqual(visit["ip"], "127.0.0.1")

        # Export CSV
        csv_data = IPLoggerService.export_csv()
        self.assertIn("Timestamp", csv_data)

    # 5. ATTACK LAB SIMULATOR
    def test_attack_lab_sandbox(self):
        # SQLi Simulation
        sqli_res = AttackLabSimulator.test_sqli_endpoint("' OR 1=1--")
        self.assertEqual(sqli_res["status"], "vulnerable")
        self.assertGreaterEqual(len(sqli_res["records_returned"]), 1)

        # XSS Simulation
        xss_res = AttackLabSimulator.test_xss_endpoint("<script>alert(1)</script>")
        self.assertEqual(xss_res["status"], "vulnerable")

        # Weak Auth Simulation
        auth_res = AttackLabSimulator.test_auth_endpoint("operator", "password123")
        self.assertTrue(auth_res["authenticated"])

    # 6. NETWORKING & SUBNET
    def test_subnet_and_dns(self):
        sub_res = SubnetCalculator.calculate_cidr("192.168.1.0/24")
        self.assertEqual(sub_res["usable_hosts"], 254)
        self.assertEqual(sub_res["netmask"], "255.255.255.0")

        dns_res = DNSAnalyzer.resolve_domain("localhost")
        self.assertIn("127.0.0.1", dns_res["records"]["A"])

    # 7. FASTAPI REST API ENDPOINTS
    def test_rest_api_endpoints(self):
        # Overview
        resp = self.client.get("/api/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("telemetry", data)
        self.assertIn("correlation", data)

        # Telemetry
        resp = self.client.get("/api/telemetry")
        self.assertEqual(resp.status_code, 200)

        # Lab Scenarios
        resp = self.client.get("/api/lab/scenarios")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(len(resp.json()), 1)

        # Security Headers on Response
        self.assertEqual(resp.headers.get("X-Infinity-Shield"), "Active")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

if __name__ == "__main__":
    unittest.main()
