from pathlib import Path
r=Path(__file__).parent
s=(r/'assertions_local.sql').read_text()
checks={'exact expired rejection':"err <> 'invalid request expiry'" in s,'11-minute rejection':"interval '11 minutes'" in s,'valid request insert':"interval '2 minutes'" in s,'fail-closed finalizer':"err <> 'device approval disabled until trusted verifier integration'" in s,'3 role checks':"['anon','authenticated','service_role']" in s,'privilege checks':all(t in s for t in ['has_schema_privilege','has_table_privilege','has_function_privilege']),'stop on SQL errors':'\\set ON_ERROR_STOP on' in s}
for n,v in checks.items():print(('PASS' if v else 'FAIL'),n)
assert all(checks.values())
print(f'{len(checks)}/{len(checks)} static checks passed; PostgreSQL not executed')
