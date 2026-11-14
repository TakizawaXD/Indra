"""
Unit test for Indra Exclusive License Guard.
"""

import unittest
from core.license import IndraLicenseGuard, AUTHORIZED_INDRA_KEY

class TestIndraLicense(unittest.TestCase):

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

