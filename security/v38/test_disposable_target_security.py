"""Regression tests for the fail-closed V38 disposable database URL guard."""
import unittest
from validate_target import validate

BASE = "postgresql://postgres:disposable-ci-only@127.0.0.1:5432/bharathlink_disposable_v30"

class DisposableTargetSecurityTests(unittest.TestCase):
    def assert_rejected(self, url, env=None):
        ok, reason = validate(url, {} if env is None else env)
        self.assertFalse(ok, (url, reason))

    def test_valid_disposable_url(self):
        ok, _ = validate(BASE, {})
        self.assertTrue(ok)

    def test_rejects_remote_and_local_aliases(self):
        for host in ("localhost", "::1", "127.0.0.2", "10.0.0.1",
                     "supabase.co", "0x7f000001", "2130706433"):
            with self.subTest(host=host):
                self.assert_rejected(BASE.replace("127.0.0.1", host))

    def test_rejects_wrong_database_and_options(self):
        for url in (BASE.replace("bharathlink_disposable_v30", "postgres"),
                    BASE + "?sslmode=disable", BASE + "#fragment",
                    BASE.replace(":5432/", "/"),
                    BASE.replace("postgresql:", "https:")):
            with self.subTest(url=url):
                self.assert_rejected(url)

    def test_rejects_libpq_overrides(self):
        for key, value in (("PGHOST", "localhost"),
                           ("PGSERVICE", "production"),
                           ("PGOPTIONS", "-c search_path=public"),
                           ("PGPASSWORD", "override"),
                           ("PGAPPNAME", "bharathlink-v38-ci")):
            with self.subTest(key=key):
                self.assert_rejected(BASE, {key: value})

    def test_ci_application_name_requires_actions_context(self):
        self.assertTrue(validate(BASE, {"PGAPPNAME": "bharathlink-v38-ci",
                                         "GITHUB_ACTIONS": "true"})[0])
        self.assert_rejected(BASE, {"PGAPPNAME": "bharathlink-v38-ci",
                                    "GITHUB_ACTIONS": "false"})

if __name__ == "__main__":
    unittest.main()
