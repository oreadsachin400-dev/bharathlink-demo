"""Offline negative/positive contract tests for read-only installed KeyPrep signer inspection.

Every ADB/apksigner/aapt call is synthetic. Never contacts a physical phone.
"""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/"scripts"
sys.path.insert(0,str(SCRIPTS))
import audit_installed_keyprep_signer as module

VALID_DEVICES="List of devices attached\nR58N1234567\tdevice\n"
VALID_PATH="package:/data/app/~~abcDEF/verylong==/base.apk\n"
VALID_BADGING=(
    "package: name='com.bharathlink.app.test.keypreponly' "
    "versionCode='40' versionName='TEST'\n"
)
VALID_SIGNER=(
    "Signer #1 certificate SHA-256 digest: " +
    module.INSTALLED_CANDIDATE_CERT_SHA256 + "\n"
)


class SyntheticRunner:
    def __init__(self, devices=VALID_DEVICES, path=VALID_PATH,
                 signing=VALID_SIGNER, badging=VALID_BADGING,
                 fail_pull=False):
        self.devices=devices
        self.path=path
        self.signing=signing
        self.badging=badging
        self.fail_pull=fail_pull
        self.commands=[]
        self.copied_file=None

    def __call__(self, args, timeout):
        self.commands.append(tuple(args))
        if args==["adb","devices"]:
            return self.devices
        if args[:6]==["adb","-s","R58N1234567","shell","pm","path"]:
            if args[6]!=module.PKG:
                raise AssertionError("Wrong KeyPrep package")
            return self.path
        if args[:4]==["adb","-s","R58N1234567","pull"]:
            self.copied_file=Path(args[5])
            if not self.fail_pull:
                self.copied_file.write_bytes(b"TEST_APK_ONLY_NOT_REAL"*100)
            return "1 file pulled."
        if args[0]=="apksigner":
            assert args[1:4]==["verify","--verbose","--print-certs"]
            assert Path(args[4]).exists()
            return self.signing
        if args[0]=="aapt":
            assert args[1:3]==["dump","badging"]
            assert Path(args[3]).exists()
            return self.badging
        raise AssertionError("Unexpected or mutating command: "+str(args))


class InstalledKeyPrepSignerTests(unittest.TestCase):
    def test_success_reads_only_installed_public_apk_and_never_authorizes_update(self):
        fake=SyntheticRunner()
        result=module.audit(runner=fake)
        self.assertEqual(result["verdict"],"PHONE_APK_CERT_MATCHES_ARCHIVED_KEYPREP_V40")
        self.assertEqual(result["package"],module.PKG)
        self.assertEqual(result["installed_version_code"],40)
        self.assertEqual(result["installed_certificate_sha256"],
                         module.INSTALLED_CANDIDATE_CERT_SHA256)
        for key in ("safe_update_authorized","play_protect_clearance_verified",
                    "original_private_signing_key_verified_available",
                    "trusted_device_approved"):
            self.assertFalse(result[key],key)
        self.assertTrue(result["local_apk_copy_deleted"])
        self.assertFalse(fake.copied_file.exists())
        self.assertEqual(len(fake.commands),5)
        self.assertEqual(fake.commands[1][3:6],("shell","pm","path"))
        self.assertTrue(all(isinstance(cmd,tuple) for cmd in fake.commands))
        all_args=" ".join(" ".join(cmd).lower() for cmd in fake.commands)
        for forbidden in ("install","uninstall","clear","root","run-as",
                          "shell sh","keystore","auth/","otp","su","am force-stop"):
            self.assertNotIn(forbidden,all_args)

    def test_unauthorized_phone_denied_before_app_lookup(self):
        fake=SyntheticRunner(devices="List of devices attached\nR58N1234567\tunauthorized\n")
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)
        self.assertEqual(len(fake.commands),1)

    def test_no_phone_denied(self):
        fake=SyntheticRunner(devices="List of devices attached\n\n")
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)
        self.assertEqual(len(fake.commands),1)

    def test_two_connected_phones_denied(self):
        fake=SyntheticRunner(devices="List of devices attached\nR58N1234567\tdevice\nA1B2C3\tdevice\n")
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)
        self.assertEqual(len(fake.commands),1)

    def test_unexpected_pm_path_and_path_traversal_denied(self):
        for path in ("package:/data/user/0/com.example/private.xml\n",
                     "package:/data/app/../../data/user/0/private/base.apk\n",
                     "package:/data/app/evil path/base.apk\n",
                     "package:/data/app/a/base.apk\npackage:/data/app/b/base.apk\n",
                     ""):
            fake=SyntheticRunner(path=path)
            with self.subTest(path=path),self.assertRaises(module.AuditBlocked):
                module.audit(runner=fake)
            self.assertEqual(len(fake.commands),2)

    def test_wrong_installed_signing_certificate_denied_and_temp_removed(self):
        signing=VALID_SIGNER.replace(module.INSTALLED_CANDIDATE_CERT_SHA256,"1"*64)
        fake=SyntheticRunner(signing=signing)
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)
        self.assertFalse(fake.copied_file.exists())

    def test_ambiguous_multiple_signers_denied(self):
        fake=SyntheticRunner(signing=VALID_SIGNER+
            "Signer #2 certificate SHA-256 digest: "+("a"*64)+"\n")
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)

    def test_wrong_package_and_version_denied(self):
        for badging in (
            VALID_BADGING.replace(module.PKG,"com.other.app"),
            VALID_BADGING.replace("versionCode='40'","versionCode='39'"),
            VALID_BADGING.replace("versionCode='40'","versionCode='41'"),
            "package: name='com.bharathlink.app.test.keypreponly' versionCode='bad'\n",
            VALID_BADGING+VALID_BADGING
        ):
            fake=SyntheticRunner(badging=badging)
            with self.subTest(badging=badging),self.assertRaises(module.AuditBlocked):
                module.audit(runner=fake)
            self.assertFalse(fake.copied_file.exists())

    def test_failed_pull_denied_without_fallback_or_installer(self):
        fake=SyntheticRunner(fail_pull=True)
        with self.assertRaises(module.AuditBlocked):
            module.audit(runner=fake)
        self.assertEqual(len(fake.commands),3)

    def test_missing_platform_tool_denied_without_stacktrace_of_sensitive_command(self):
        with self.assertRaises(module.AuditBlocked):
            module.safe_run(["definitely_missing_local_adb_testing_tool_223456"],1)

    def test_no_arguments_or_phone_access_on_import(self):
        self.assertTrue(callable(module.audit))
        self.assertFalse(any(x in module.__dict__ for x in ("connected_device", "jwt", "otp")))


if __name__=="__main__":
    unittest.main()
