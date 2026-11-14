"""
GOJO INFINITY SECURITY ∞ — COMPREHENSIVE AUTOMATED TEST SUITE
Tests all subsystems: Database, Event Bus, Infinity Shield, Blue Recon,
Red Operations, Purple Intel, IP Intelligence, Attack Lab, API Endpoints, Reports.
"""

# --- Test isolation: runtime data (DB, logs, reports) goes to a temporary dir ---
import os
import tempfile
os.environ.setdefault("GOJO_DATA_DIR", tempfile.mkdtemp(prefix="indra_test_"))
os.environ.setdefault("GOJO_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")
os.environ.pop("GOJO_API_TOKEN", None)
# -----------------------------------------------------------------------------

import unittest
import asyncio
from unittest import mock
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import init_db, SessionLocal, Project, AuthorizedTarget
from core.permissions import TargetAuthorizer
from techniques.infinity.shield import infinity_shield
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from laboratory.web_lab import AttackLabSimulator
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer

class TestGojoComprehensiveSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        # API tests run unlocked regardless of whether a license key exists on this machine
        cls._license_patch = mock.patch("core.license.IndraLicenseGuard.verify_license", return_value=True)
        cls._license_patch.start()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls._license_patch.stop()

    def test_locked_platform_rejects_api(self):
        with mock.patch("core.license.IndraLicenseGuard.verify_license", return_value=False):
            resp = self.client.get("/api/telemetry")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_no_web_interface(self):
        resp = self.client.get("/")
        self.assertEqual(resp.json()["interface"], "terminal")
        self.assertEqual(self.client.get("/static/js/app.js").status_code, 404)

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

    # 8. HARDENING REGRESSION TESTS
    def test_loopback_is_never_banned(self):
        with self.assertRaises(ValueError):
            infinity_shield.ban_ip("127.0.0.1")
        with self.assertRaises(ValueError):
            infinity_shield.ban_ip("not-an-ip")
        resp = self.client.post("/api/infinity/ban", json={"ip_address": "127.0.0.1"})
        self.assertEqual(resp.status_code, 400)

        # Repeated attacks from loopback are blocked but never auto-banned
        for _ in range(8):
            infinity_shield.inspect_request("127.0.0.1", "/x", "GET", query_string="q=%27%20OR%201=1--")
        self.assertFalse(infinity_shield.is_ip_banned("127.0.0.1"))

    def test_ban_endpoint_returns_rule(self):
        resp = self.client.post("/api/infinity/ban", json={"ip_address": "203.0.113.77", "duration_minutes": 5})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["banned_ip"], "203.0.113.77")
        self.assertTrue(infinity_shield.unban_ip("203.0.113.77"))

    def test_scan_out_of_scope_is_forbidden(self):
        resp = self.client.post("/api/blue/scan", json={"target": "198.51.100.200"})
        self.assertEqual(resp.status_code, 403)
        resp = self.client.post("/api/blue/scan", json={"target": "127.0.0.1", "ports": [0]})
        self.assertEqual(resp.status_code, 422)

    def test_cidr_scope_authorizes_subnets(self):
        with SessionLocal() as db:
            proj = Project(name="Project_CIDR_Subnet", description="Subnet scope")
            db.add(proj)
            db.commit()
            db.refresh(proj)
            db.add(AuthorizedTarget(project_id=proj.id, target="10.20.0.0/16", target_type="cidr", authorization_notes="test"))
            db.commit()
            try:
                self.assertTrue(TargetAuthorizer.is_target_authorized("10.20.5.0/24")[0])
                self.assertFalse(TargetAuthorizer.is_target_authorized("10.21.0.0/24")[0])
            finally:
                db.delete(proj)
                db.commit()

    def test_subnet_host_list_is_bounded(self):
        hosts = SubnetCalculator.get_host_list("10.0.0.0/8", max_hosts=128)
        self.assertEqual(len(hosts), 128)

    def test_untrusted_host_header_rejected(self):
        resp = self.client.get("/api/telemetry", headers={"Host": "evil.example.com"})
        self.assertEqual(resp.status_code, 400)

    def test_no_wildcard_cors(self):
        resp = self.client.get("/api/telemetry", headers={"Origin": "https://evil.example.com"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in resp.headers.keys()})

    def test_report_html_is_escaped(self):
        from backend.database import Vulnerability
        with SessionLocal() as db:
            v = Vulnerability(title="<script>alert(1)</script>", severity="LOW", target="t", description="d")
            db.add(v)
            db.commit()
            vid = v.id
        try:
            report = purple_intel.generate_unified_security_report(project_name="<img src=x>")
            with open(report["pdf_report_path"], encoding="utf-8") as f:
                html_doc = f.read()
            self.assertNotIn("<script>alert(1)</script>", html_doc)
            self.assertNotIn("<img src=x>", html_doc)
            self.assertIn("&lt;script&gt;", html_doc)
        finally:
            with SessionLocal() as db:
                db.query(Vulnerability).filter(Vulnerability.id == vid).delete()
                db.commit()

    def test_api_token_enforced_when_configured(self):
        from core.config import settings
        settings.API_TOKEN = "unit-test-token"
        try:
            self.assertEqual(self.client.get("/api/telemetry").status_code, 401)
            ok = self.client.get("/api/telemetry", headers={"X-API-Key": "unit-test-token"})
            self.assertEqual(ok.status_code, 200)
        finally:
            settings.API_TOKEN = ""

if __name__ == "__main__":
    unittest.main()
