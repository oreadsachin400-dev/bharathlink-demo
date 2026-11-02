import unittest
from scripts.check_keyprep_signing import (
    check_report, INSTALLED_CANDIDATE_CERT_SHA256
)
EXPECTED=INSTALLED_CANDIDATE_CERT_SHA256
OTHER="6d4e8cf80681b219e01af0da655d0d47b51c1a6fd9822becb1dc48ede9434eda"

def report(fingerprint):
    return (
        "Signer #1 certificate DN: C=US, O=Android, CN=Android Debug\\n"
        f"Signer #1 certificate SHA-256 digest: {fingerprint}\\n"
    ).replace("\\n","\n")

class SigningGateTests(unittest.TestCase):
    def test_archived_keyprep_only_candidate_certificate(self):
        self.assertTrue(check_report(report(EXPECTED))[0])

    def test_previous_keyprep_certificate_mismatch_blocked(self):
        good, msg=check_report(report(OTHER))
        self.assertFalse(good)
        self.assertIn("BLOCKED",msg)

    def test_missing_report_rejected(self):
        self.assertFalse(check_report("no signer")[0])

    def test_multiple_signers_rejected(self):
        r=report(EXPECTED)+report(EXPECTED).replace("#1","#2")
        self.assertFalse(check_report(r)[0])

    def test_malformed_fingerprint_rejected(self):
        self.assertFalse(check_report(report("deadbeef"))[0])

    def test_wrong_case_normalized_without_relaxing_value(self):
        self.assertTrue(check_report(report(EXPECTED.upper()))[0])

    def test_wrong_sha256_even_with_matching_sha1_line_rejected(self):
        self.assertFalse(check_report(report(OTHER)+
             "Signer #1 certificate SHA-1 digest: "+
             "4f363d9c52b07464f16a019b68db940b3347ffa5\n")[0])

if __name__ == "__main__":
    unittest.main()
