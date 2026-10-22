import unittest
from pathlib import Path
class LegacyEnrollmentCallerAudit(unittest.TestCase):
 def test_legacy_test_page_is_not_approval_capable(self):
  page=(Path(__file__).resolve().parents[2]/'index.html').read_text(encoding='utf-8')
  self.assertIn("RPC: 'register_e2ee_v2_device'",page)
  self.assertIn("RPC_PARAMS: Object.freeze(['p_device_id', 'p_signing_public_key', 'p_curve25519_public_key'])",page)
  self.assertIn('const res = await this.callRpc(this.RPC, payload)',page)
  # This is an inventory regression, not evidence of a secure production path.
  # On migration, replace this with a signed approval flow and update the test.
if __name__=='__main__': unittest.main()
