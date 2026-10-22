import unittest
from validate_target import validate
BASE='postgresql://tester:password@127.0.0.1:5432/bharathlink_disposable_v30'
class GuardTests(unittest.TestCase):
    def test_allowed(self):
        self.assertTrue(validate(BASE,{})[0])
    def test_bad_targets(self):
        for url in [BASE.replace('127.0.0.1','localhost'),BASE.replace('127.0.0.1','[::1]'),BASE.replace('127.0.0.1','example.com'),BASE.replace('5432',''),BASE.replace('disposable_v30','production'),BASE+'?host=remote',BASE+'#fragment',BASE.replace('tester:password','tester'),BASE.replace('postgresql:','https:')]:
            with self.subTest(url=url): self.assertFalse(validate(url,{})[0])
    def test_libpq_overrides(self):
        for key in ('PGHOST','PGHOSTADDR','PGSERVICE','PGOPTIONS','PGPASSWORD','PGPASSFILE'):
            with self.subTest(key=key): self.assertFalse(validate(BASE,{key:'remote'})[0])
if __name__=='__main__': unittest.main()
