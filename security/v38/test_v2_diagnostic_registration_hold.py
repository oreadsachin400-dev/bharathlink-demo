"""Fail-closed regression for the separate V2 diagnostic device-registration path.

This checks isolated branch source only. It does not authorize or deploy enrollment.
Run: python3 -m unittest security/v38/test_v2_diagnostic_registration_hold.py
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "index.html"


class V2DiagnosticRegistrationHoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("const E2EEV2DeviceTest = {")
        end = source.index("const LocationShare = {", start)
        cls.section = source[start:end]
        cls.run = cls.section.split("  async run() {", 1)[1].split("  async forget() {", 1)[0]

    def test_no_legacy_registration_rpc_called_from_diagnostic_run(self):
        self.assertNotRegex(self.run, r"\b(?:this\.)?callRpc\s*\(")
        self.assertNotRegex(self.run, r"\bfetch\s*\(")
        self.assertNotIn("register_e2ee_v2_device(", self.run)

    def test_diagnostic_run_explicitly_fails_closed(self):
        self.assertIn("V38 SECURITY HOLD: unsigned legacy V2 registration disabled", self.run)
        self.assertRegex(self.run, r"r\.rpc\s*=\s*['\"]fail['\"]")

    def test_no_indirect_registration_through_legacy_rpc_name(self):
        # A dormant helper may remain for diagnostics, but the run path must
        # never reference the registration RPC name or dynamically call it.
        self.assertNotIn("this.RPC", self.run)
        self.assertNotIn("this.buildPayload", self.run)

    def test_browser_has_no_secret_service_role_configuration(self):
        self.assertIn("this.assertBrowserSafeKey()", self.run)


if __name__ == "__main__":
    unittest.main()
