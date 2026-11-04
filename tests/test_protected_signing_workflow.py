import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RELEASE=ROOT/".github/workflows/keyprep-protected-signing.yml"
TEMPLATE=ROOT/"docs/TEST-Email-OTP-Dual-Mode-Template-REVIEW-ONLY.md"

class ProtectedSigningWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow=RELEASE.read_text(encoding="utf-8")
        cls.otp=TEMPLATE.read_text(encoding="utf-8")

    def test_manual_signing_only(self):
        self.assertIn("workflow_dispatch:",self.workflow)
        self.assertNotIn("pull_request:",self.workflow)
        self.assertNotIn("\n  push:",self.workflow)

    def test_protected_environment_and_readonly_repository(self):
        self.assertIn("name: keyprep-signing",self.workflow)
        self.assertIn("contents: read",self.workflow)
        self.assertIn("persist-credentials: false",self.workflow)
        self.assertIn("if: false",self.workflow)
        self.assertIn("Release HOLD: Google Play Protect harmful-app finding is unresolved",self.workflow)

    def test_no_protected_signing_or_apk_upload_can_run_before_clearance(self):
        self.assertIn("    if: false",self.workflow)
        self.assertIn("Play Protect",self.workflow)

    def test_requires_all_four_secrets(self):
        for secret in (
            "secrets.BHARATHLINK_KEYPREP_KEYSTORE_B64",
            "secrets.BHARATHLINK_KEYPREP_STORE_PASSWORD",
            "secrets.BHARATHLINK_KEYPREP_KEY_PASSWORD",
            "secrets.BHARATHLINK_KEYPREP_KEY_ALIAS"
        ):
            self.assertIn(secret,self.workflow)
        self.assertIn("Fail closed without explicitly recovered original signing key",self.workflow)

    def test_certificate_package_version_validation_before_upload(self):
        checker=self.workflow.index("python3 scripts/check_keyprep_release.py")
        uploader=self.workflow.index("uses: actions/upload-artifact@v4")
        self.assertLess(checker,uploader)
        self.assertIn('apksigner" sign',self.workflow)
        self.assertIn('apksigner" verify',self.workflow)
        self.assertIn('aapt" dump badging',self.workflow)

    def test_signing_keystore_removed_from_runner(self):
        self.assertIn("umask 077",self.workflow)
        self.assertIn('trap \'rm -rf "$tmp"\' EXIT',self.workflow)
        self.assertNotIn("set -x",self.workflow)

    def test_template_keeps_existing_magic_link_and_adds_otp(self):
        self.assertIn("{{ .Token }}",self.otp)
        self.assertIn("{{ .ConfirmationURL }}",self.otp)
        self.assertIn("NOT DEPLOYED",self.otp)
        self.assertIn("Do not alter or deploy",self.otp)

if __name__=="__main__":
    unittest.main()
