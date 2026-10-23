"""Static regression: security branch must not silently enable enrollment.
Checks source files, not the deployed Netlify site or Supabase project.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

class EnrollmentReleaseHold(unittest.TestCase):
 def test_main_web_enrollment_is_fail_closed(self):
  page=(ROOT/'index.html').read_text(encoding='utf-8')
  self.assertIn('Messaging is locked until trusted-device approval and secure enrollment are available.',page)
  self.assertIn('V38 SECURITY HOLD: unsigned legacy V2 registration disabled',page)
 def test_server_composition_not_a_browser_import(self):
  page=(ROOT/'index.html').read_text(encoding='utf-8')
  self.assertNotIn('v39_trusted_enrollment_composition_REFERENCE_NOT_DEPLOYED.mjs',page)
 def test_first_device_authority_explicitly_disabled(self):
  code=(ROOT/'security/v38/v39_bootstrap_recovery_authority_REFERENCE_NOT_DEPLOYED.mjs').read_text(encoding='utf-8')
  self.assertIn('initial and recovery enrollment disabled pending independent authority',code)
 def test_no_release_claim_in_android_launcher(self):
  doc=(ROOT/'security/v38/TEST_SUPABASE_V39_COMPATIBILITY_GATE_2026-10-23.md').read_text(encoding='utf-8')
  self.assertIn('SECURITY HOLD',doc)

if __name__=='__main__':
 unittest.main()
