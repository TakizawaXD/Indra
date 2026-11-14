"""
Test for Hollow Purple Protocol end-to-end execution.
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
from techniques.hollow_purple.protocol import HollowPurpleProtocol
from backend.database import init_db

class TestHollowPurple(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_hollow_purple_local_convergence(self):
        res = asyncio.run(HollowPurpleProtocol.execute("127.0.0.1"))
        self.assertEqual(res["target"], "127.0.0.1")
        self.assertIn("blue_recon", res["phases"])
        self.assertIn("red_operations", res["phases"])
        self.assertIn("purple_correlation", res["phases"])
        self.assertIn("infinity_shield", res["phases"])
        self.assertIn("six_eyes_synthesis", res["phases"])
        self.assertIn(res["phases"]["six_eyes_synthesis"]["posture_assessment"], ["SECURE", "ATTENTION_REQUIRED"])

if __name__ == "__main__":
    unittest.main()
