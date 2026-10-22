import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from enrollment_authorization_reference import Enrollment, VerifiedApproval, authorize

class EnrollmentAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 22, tzinfo=timezone.utc)
        self.e = Enrollment("user1","device2","sign-hash","x-hash","device1","nonce1",self.now+timedelta(minutes=5))
        self.a = VerifiedApproval(self.e,True,True,False)
        self.kw = dict(expected_user="user1",expected_device="device2",
                       expected_signing_hash="sign-hash",expected_x25519_hash="x-hash",
                       now=self.now,consumed_nonces=frozenset())
    def check(self,a=None,**overrides):
        return authorize(a or self.a,**(self.kw | overrides))
    def test_valid_reference(self): self.assertTrue(self.check())
    def test_unsigned(self): self.assertFalse(self.check(replace(self.a,signature_verified=False)))
    def test_untrusted(self): self.assertFalse(self.check(replace(self.a,approver_trusted=False)))
    def test_revoked(self): self.assertFalse(self.check(replace(self.a,approver_revoked=True)))
    def test_wrong_user(self): self.assertFalse(self.check(expected_user="other"))
    def test_wrong_device(self): self.assertFalse(self.check(expected_device="other"))
    def test_wrong_signing_key(self): self.assertFalse(self.check(expected_signing_hash="other"))
    def test_wrong_x25519_key(self): self.assertFalse(self.check(expected_x25519_hash="other"))
    def test_expired(self): self.assertFalse(self.check(now=self.e.expires_at))
    def test_replay(self): self.assertFalse(self.check(consumed_nonces=frozenset({"nonce1"})))
    def test_wrong_purpose(self): self.assertFalse(self.check(replace(self.a,enrollment=replace(self.e,purpose="payment"))))
    def test_empty_nonce(self): self.assertFalse(self.check(replace(self.a,enrollment=replace(self.e,nonce=""))))
    def test_self_approval(self):
        self.assertFalse(self.check(replace(self.a, enrollment=replace(self.e, approver_device_id="device2"))))
    def test_blank_approver(self):
        self.assertFalse(self.check(replace(self.a, enrollment=replace(self.e, approver_device_id=" "))))
    def test_blank_candidate(self):
        self.assertFalse(self.check(replace(self.a, enrollment=replace(self.e, candidate_device_id=""))))
    def test_excessive_lifetime(self):
        self.assertFalse(self.check(replace(self.a, enrollment=replace(self.e, expires_at=self.now+timedelta(minutes=11)))))
    def test_naive_expiry(self): self.assertFalse(self.check(replace(self.a,enrollment=replace(self.e,expires_at=datetime(2026,10,22)))))
if __name__=="__main__": unittest.main()
