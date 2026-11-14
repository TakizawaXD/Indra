"""
Unit test for Indra Exclusive License Guard.
"""

# --- Test isolation: runtime data (DB, logs, reports) goes to a temporary dir ---
import os
import tempfile
os.environ.setdefault("GOJO_DATA_DIR", tempfile.mkdtemp(prefix="indra_test_"))
os.environ.setdefault("GOJO_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")
os.environ.pop("GOJO_API_TOKEN", None)
# -----------------------------------------------------------------------------

import unittest
from core.license import IndraLicenseGuard, AUTHORIZED_KEY_SHA256, hash_key

class TestIndraLicense(unittest.TestCase):

    def test_hash_is_sha256_hex(self):
        self.assertEqual(len(AUTHORIZED_KEY_SHA256), 64)
        self.assertNotEqual(hash_key("INVALID-KEY-123"), AUTHORIZED_KEY_SHA256)

    @unittest.skipUnless(IndraLicenseGuard.get_current_key(), "No license key configured (config/license.key or INDRA_LICENSE_KEY)")
    def test_authorized_key_validation(self):
        self.assertTrue(IndraLicenseGuard.verify_license())

    def test_unauthorized_key_rejection(self):
        import os
        old_env = os.environ.get("INDRA_LICENSE_KEY")
        try:
            os.environ["INDRA_LICENSE_KEY"] = "INVALID-KEY-123"
            self.assertFalse(IndraLicenseGuard.verify_license())
            with self.assertRaises(PermissionError):
                IndraLicenseGuard.enforce_license()
        finally:
            if old_env is not None:
                os.environ["INDRA_LICENSE_KEY"] = old_env
            else:
                os.environ.pop("INDRA_LICENSE_KEY", None)

if __name__ == "__main__":
    unittest.main()

