"""Static safety and readiness tests for the Windows KeyPrep-only USB certificate reader.

The reviewed Windows launcher is NOT invoked by this module: no physical
phone or USB operation can occur in a source-only unit test.
"""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"KeyPrep-Signer-Check-Windows.cmd"

class WindowsKeyPrepLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body=PATH.read_text(encoding="utf-8")
        cls.lower=cls.body.lower()

    def test_only_the_original_read_only_python_auditor_is_invoked(self):
        self.assertEqual(self.lower.count('"scripts\\audit_installed_keyprep_signer.py"'),3)
        self.assertIn('scripts\\check_keyprep_signing.py',self.lower)
        self.assertNotIn("phase7a",self.lower)

    def test_no_mutating_android_commands_and_no_installer(self):
        for bad in (
            "adb install","adb uninstall","pm clear","pm uninstall",
            "adb root","adb reboot","adb push","adb shell rm",
            "fastboot","erase","format data","disable-verity",
            "pip install","winget install","choco install",
            "curl ","wget ","invoke-webrequest","downloadfile",
            "-executionpolicy bypass","powershell -command"
        ):
            with self.subTest(command=bad):
                self.assertNotIn(bad,self.lower)

    def test_official_android_sdk_paths_and_dependency_checks(self):
        for required in (
            "%localappdata%\\android\\sdk",
            "%android_sdk_root%\\platform-tools\\adb.exe",
            "%android_home%\\platform-tools\\adb.exe",
            "platform-tools\\adb.exe",
            "apksigner.bat",
            "aapt.exe",
            "where py",
            "where python"
        ):
            with self.subTest(required=required):
                self.assertIn(required,self.lower)

    def test_fail_closed_if_any_required_component_missing(self):
        self.assertGreaterEqual(self.lower.count("goto blocked"),5)
        self.assertIn("exit /b 1",self.lower)
        self.assertIn("if errorlevel 1 goto blocked",self.lower)
        self.assertIn("if not exist \"scripts\\audit_installed_keyprep_signer.py\"",self.lower)
        self.assertIn("if not exist \"scripts\\check_keyprep_signing.py\"",self.lower)

    def test_always_preserves_original_keyprep_and_never_promises_clearance(self):
        self.assertIn("keep the original keyprep installed",self.lower)
        self.assertIn("does not confirm the private signing key",self.lower)
        self.assertIn("play protect clearance",self.lower)
        self.assertIn("do not disable play protect",self.lower)
        self.assertNotIn("safe_update_authorized=true",self.lower)

    def test_uses_no_system_wide_path_or_policy_changes(self):
        self.assertIn("setlocal enableextensions disabledelayedexpansion",self.lower)
        self.assertIn('set "path=',self.lower)
        self.assertNotIn("setx ",self.lower)
        self.assertNotIn("reg add",self.lower)
        self.assertNotIn("bcdedit",self.lower)
        self.assertNotIn("executionpolicy",self.lower)

    def test_does_not_print_adb_serial_or_personal_data(self):
        self.assertNotIn("adb devices",self.lower)
        self.assertNotIn("serial",self.lower)
        self.assertNotIn("auth/v1",self.lower)
        self.assertNotIn("otp=",self.lower)
        self.assertNotIn("token=",self.lower)

    def test_automation_can_run_noninteractive_blocked_path(self):
        self.assertIn("if not defined ci pause",self.lower)
        self.assertIn("exit /b 0",self.lower)
        self.assertIn("exit /b 1",self.lower)

if __name__=="__main__":
    unittest.main()
