import os, pathlib, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parent
URL = 'postgresql://tester:password@127.0.0.1:5432/bharathlink_disposable_v30'
class RunnerContract(unittest.TestCase):
    def invoke(self, code):
        with tempfile.TemporaryDirectory() as tmp:
            stub = pathlib.Path(tmp)/'psql'
            output = pathlib.Path(tmp)/'captured.sql'
            stub.write_text('#!/bin/sh\ncat > "$CAPTURE_SQL"\nexit '+str(code)+'\n')
            stub.chmod(0o755)
            env = {k:v for k,v in os.environ.items() if not k.startswith('PG')}
            env.update(PATH=tmp+':'+env.get('PATH',''),LOCAL_TEST_DATABASE_URL=URL,CAPTURE_SQL=str(output))
            result = subprocess.run(['bash',str(ROOT/'run_local.sh')],env=env,capture_output=True,text=True)
            return result, output.read_text() if output.exists() else ''
    def test_transaction_boundaries_and_content(self):
        result, sql = self.invoke(0)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(sql.count('BEGIN;'),1)
        self.assertEqual(sql.count('COMMIT;'),1)
        self.assertLess(sql.index('BEGIN;'),sql.index('CREATE ROLE anon'))
        self.assertLess(sql.index('CREATE ROLE anon'),sql.index('CREATE SCHEMA auth'))
        self.assertIn('REFUSED: database has existing user relations',sql)
        self.assertIn('ALL V31 LOCAL POSTGRES ASSERTIONS PASSED',sql)
    def test_psql_failure_is_not_success(self):
        result, _ = self.invoke(17)
        self.assertEqual(result.returncode,17)
    def test_invalid_url_never_invokes_psql(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub=pathlib.Path(tmp)/'psql'; marker=pathlib.Path(tmp)/'called'
            stub.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n');stub.chmod(0o755)
            env={k:v for k,v in os.environ.items() if not k.startswith('PG')}
            env.update(PATH=tmp+':'+env.get('PATH',''),LOCAL_TEST_DATABASE_URL=URL.replace('127.0.0.1','example.com'))
            result=subprocess.run(['bash',str(ROOT/'run_local.sh')],env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists())
if __name__=='__main__': unittest.main()
