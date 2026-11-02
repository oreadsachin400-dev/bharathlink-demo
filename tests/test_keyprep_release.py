import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from check_keyprep_release import check_release
from check_keyprep_signing import INSTALLED_CANDIDATE_CERT_SHA256 as CERT

def certificate(fp=CERT):
    return f"Signer #1 certificate SHA-256 digest: {fp}\n"

def package(name="com.bharathlink.app.test.keypreponly",code="41"):
    return f"package: name='{name}' versionCode='{code}' versionName='36.0.5-HF-AUTH-BIND-STAGED'\n"

class ReleaseMetadataTests(unittest.TestCase):
    def test_valid_archived_certificate_and_package(self):
        self.assertTrue(check_release(certificate(),package())[0])
    def test_missing_signing_report_denied(self):
        self.assertFalse(check_release("",package())[0])
    def test_wrong_certificate_denied(self):
        self.assertFalse(check_release(certificate("a"*64),package())[0])
    def test_wrong_app_id_denied(self):
        self.assertFalse(check_release(certificate(),package("com.bharathlink.app.test.fake"))[0])
    def test_old_version_denied(self):
        self.assertFalse(check_release(certificate(),package(code="40"))[0])
    def test_rollback_version_denied(self):
        self.assertFalse(check_release(certificate(),package(code="39"))[0])
    def test_version_code_not_numeric_denied(self):
        self.assertFalse(check_release(certificate(),package(code="4l"))[0])
    def test_two_manifest_declarations_denied(self):
        self.assertFalse(check_release(certificate(),package()+package())[0])
    def test_zero_signer_denied(self):
        self.assertFalse(check_release("Signer #2 certificate SHA-256 digest: "+CERT,package())[0])
    def test_negative_version_denied(self):
        self.assertFalse(check_release(certificate(),package(code="-99"))[0])
    def test_matching_cert_never_implies_device_trust(self):
        self.assertIn("physical phone",check_release(certificate(),package())[1])
if __name__=="__main__":
    unittest.main()
