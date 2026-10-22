#!/usr/bin/env python3
"""Fail closed before connecting to an isolated disposable PostgreSQL instance."""
import ipaddress
import os
import sys
from urllib.parse import urlsplit, unquote

EXPECTED_DB = 'bharathlink_disposable_v30'
BLOCKED_ENV = {'PGHOST','PGHOSTADDR','PGPORT','PGDATABASE','PGUSER','PGPASSWORD',
               'PGSERVICE','PGSERVICEFILE','PGOPTIONS','PGSSLMODE','PGPASSFILE',
               'PGCONNECT_TIMEOUT','PGTARGETSESSIONATTRS','PGREQUIRESSL',
               'PGCHANNELBINDING','PGAPPNAME'}

def validate(url, env):
    if any(k in env for k in BLOCKED_ENV if k != 'PGAPPNAME'):
        return False, 'libpq environment overrides are forbidden'
    if 'PGAPPNAME' in env and not (env['PGAPPNAME'] == 'bharathlink-v38-ci' and env.get('GITHUB_ACTIONS') == 'true'):
        return False, 'libpq environment overrides are forbidden'
    try:
        u = urlsplit(url)
        if u.scheme not in ('postgres', 'postgresql') or not u.hostname:
            return False, 'invalid scheme or hostname'
        if str(ipaddress.ip_address(u.hostname)) != '127.0.0.1':
            return False, 'requires literal 127.0.0.1'
        if not u.port or not (1 <= u.port <= 65535):
            return False, 'explicit port required'
        if unquote(u.path) != '/' + EXPECTED_DB:
            return False, 'wrong database'
        if not u.username or u.password is None:
            return False, 'explicit username and password required'
        if u.query or u.fragment:
            return False, 'URL options are forbidden'
        if any(x in url.lower() for x in ('supabase.co','lhaiwfdzynssgxmtlytl','fsdusofbpwdrdvgexxyw')):
            return False, 'remote project marker'
    except (ValueError, AssertionError):
        return False, 'malformed URL'
    return True, 'validated URL only; database guard must also pass'

if __name__ == '__main__':
    ok, reason = validate(os.environ.get('LOCAL_TEST_DATABASE_URL', ''), os.environ)
    print(('PASS: ' if ok else 'REFUSED: ') + reason, file=sys.stdout if ok else sys.stderr)
    sys.exit(0 if ok else 2)
