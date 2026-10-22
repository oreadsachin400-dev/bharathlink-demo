import unittest
from pathlib import Path
p=Path(__file__).parent
class BootstrapContract(unittest.TestCase):
 def test_roles_declared(self):
  sql=(p/'bootstrap_local.sql').read_text()
  for role in ('anon','authenticated','service_role'):
   self.assertEqual(sql.count(f'CREATE ROLE {role} NOLOGIN;'),1)
 def test_abort_on_sql_error(self):
  sh=(p/'run_local.sh').read_text()
  self.assertIn('ON_ERROR_STOP=1',sh)
  self.assertIn('BEGIN;',sh)
  self.assertIn('COMMIT;',sh)
 def test_no_live_target(self):
  from validate_target import validate
  self.assertFalse(validate('postgresql://u:p@fsdusofbpwdrdvgexxyw.supabase.co:5432/bharathlink_disposable_v30',{})[0])
if __name__=='__main__': unittest.main()
