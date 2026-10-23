"""Regression guard for isolated V38 web messaging enrollment security hold.

Run: python3 -m unittest security/v38/test_web_messaging_enrollment_boundary.py
This checks repository source, not deployed TEST or production.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "index.html"

class MessagingEnrollmentBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        start = cls.source.index("const E2EEBackend = {")
        end = cls.source.index("const E2EEV2DeviceTest = {", start)
        cls.messaging = cls.source[start:end]

    def test_no_unsigned_direct_messaging_device_insert(self):
        self.assertNotRegex(self.messaging, r"/rest/v1/messaging_devices['\"][\s\S]{0,150}method\s*:\s*['\"]POST")
        self.assertNotIn("device_label:'BharathLink web E2EE v2'", self.messaging)

    def test_existing_active_local_device_reused(self):
        self.assertIn("is_my_messaging_device_active", self.messaging)
        self.assertIn("if(st===true)return local;", self.messaging)

    def test_new_device_fails_closed(self):
        self.assertIn("Messaging is locked until trusted-device approval and secure enrollment are available.", self.messaging)
        self.assertNotIn("crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])", self.messaging.split("async activate(){",1)[1].split("async importPub(",1)[0])

if __name__ == "__main__":
    unittest.main()
