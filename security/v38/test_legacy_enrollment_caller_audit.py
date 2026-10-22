import unittest
from pathlib import Path

class LegacyEnrollmentCallerAudit(unittest.TestCase):
 def test_unsigned_legacy_registration_is_fail_closed(self):
  page=(Path(__file__).resolve().parents[2]/'index.html').read_text(encoding='utf-8')
  start=page.index('const E2EEV2DeviceTest = {')
  end=page.index('/* =====================================================================',start)
  block=page[start:end]
  self.assertIn("RPC: 'register_e2ee_v2_device'",block)
  run=block[block.index('  async run() {'):block.index('  async forget() {')]
  self.assertIn('V38 SECURITY HOLD: unsigned legacy V2 registration disabled',run)
  self.assertIn("r.rpc = 'fail'",run)
  self.assertNotIn('this.callRpc(',run)
  self.assertNotIn('this.buildPayload(local)',run)
  self.assertNotIn('verifiedReturnedId =',run)
if __name__=='__main__': unittest.main()
