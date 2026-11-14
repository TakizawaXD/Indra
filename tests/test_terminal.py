"""
Tests for the terminal-only interface: dashboard views and API server control.
"""

# --- Test isolation: runtime data (DB, logs, reports) goes to a temporary dir ---
import os
import tempfile
os.environ.setdefault("GOJO_DATA_DIR", tempfile.mkdtemp(prefix="indra_test_"))
os.environ.setdefault("GOJO_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")
os.environ.pop("GOJO_API_TOKEN", None)
# -----------------------------------------------------------------------------

import socket
import unittest
from unittest import mock

import httpx

from backend.database import init_db
from terminal import formatter
from terminal.commands import GojoCommandHandler
from terminal.server_control import api_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestTerminalInterface(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def run_cmd(self, cmd: str) -> str:
        with formatter.console.capture() as capture:
            GojoCommandHandler.execute(cmd)
        return capture.get()

    def test_dashboard_renders(self):
        out = self.run_cmd("dashboard")
        self.assertIn("PANEL DE CONTROL", out)
        self.assertIn("Infinity Shield", out)
        self.assertIn("Riesgo Global", out)

    def test_config_and_help(self):
        self.assertIn("CONFIGURACIÓN ACTIVA", self.run_cmd("config"))
        help_out = self.run_cmd("help")
        for command in ("dashboard", "monitor", "server", "blue web"):
            self.assertIn(command, help_out)

    def test_network_topology_renders(self):
        self.assertIn("TOPOLOGÍA DE RED", self.run_cmd("network topology"))

    def test_invalid_server_port(self):
        self.assertIn("puerto", self.run_cmd("server start abc").lower())

    def test_numbered_menu_navigation(self):
        from terminal.shell import run_shell

        class FakeIO:
            def __init__(self, answers):
                self.answers = list(answers)

            def set_commands(self, licensed):
                pass

            def _next(self, _text):
                if not self.answers:
                    raise EOFError
                return self.answers.pop(0)

            prompt = _next
            ask = _next

        # 3 = Infinity Shield, 2 = ban IP (asks the IP), 0 = back, 99 = invalid, 13 -> 1 = lab list, 0, 0 = exit
        answers = ["3", "2", "203.0.113.44", "0", "99", "13", "1", "0", "0"]
        with mock.patch("core.license.IndraLicenseGuard.verify_license", return_value=True):
            with formatter.console.capture() as capture:
                run_shell(io=FakeIO(answers))
        out = capture.get()
        self.assertIn("MENÚ PRINCIPAL", out)
        self.assertIn("203.0.113.44 banned", out)
        self.assertIn("Opción 99 no válida", out)
        self.assertIn("SAFE ATTACK LAB SCENARIOS", out)
        self.assertIn("Cerrando sesion", out)

        from techniques.infinity.shield import infinity_shield
        infinity_shield.unban_ip("203.0.113.44")

    def test_locked_menu_offers_only_key(self):
        from terminal.shell import run_shell

        class FakeIO:
            answers = ["5", "0"]

            def set_commands(self, licensed):
                pass

            def prompt(self, _text):
                if not self.answers:
                    raise EOFError
                return self.answers.pop(0)

            ask = prompt

        with mock.patch("core.license.IndraLicenseGuard.verify_license", return_value=False):
            with formatter.console.capture() as capture:
                run_shell(io=FakeIO())
        out = capture.get()
        self.assertIn("SISTEMA BLOQUEADO", out)
        self.assertIn("Insertar llave", out)

    def test_server_start_and_stop_from_terminal(self):
        port = _free_port()
        with mock.patch("core.license.IndraLicenseGuard.verify_license", return_value=True):
            res = api_server.start(port)
            try:
                self.assertTrue(res["ok"], res["message"])
                self.assertTrue(api_server.is_running)
                health = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5)
                self.assertEqual(health.status_code, 200)
                self.assertIn("ACTIVO", self.run_cmd("server status"))
            finally:
                stop = api_server.stop()
        self.assertTrue(stop["ok"], stop["message"])
        self.assertFalse(api_server.is_running)


if __name__ == "__main__":
    unittest.main()
