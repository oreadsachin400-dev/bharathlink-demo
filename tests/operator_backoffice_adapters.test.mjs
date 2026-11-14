import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedPgBackofficeAdapters, ACTIVE_SESSION_SQL, OPERATOR_SCOPE_SQL }
  from '../security/review-only/operator_backoffice_adapters.mjs';
import { createOperatorAuthGate, OperatorAuthDenied } from '../security/review-only/operator_auth_gate.mjs';

const USER = '11111111-1111-4111-8111-111111111111';
const SESSION = '22222222-2222-4222-8222-222222222222';
const ADMIN = '33333333-3333-4333-8333-333333333333';
const URL = 'https://fsdusofbpwdrdvgexxyw.supabase.co';
const NOW = 1_800_000_000;

function fakeDb(result) {
  const calls = [];
  const db = { async query(sql, args) {
    calls.push({ sql, args });
    if (result instanceof Error) throw result;
    return typeof result === 'function' ? result(sql, args) : result;
  } };
  return { db, calls, adapters: createTrustedPgBackofficeAdapters({ db }) };
}

test('session query matches confirmed AAL2 unbanned user and unexpired session', () => {
  for (const key of ['auth.sessions', 'auth.users', 's.aal::text', 's.not_after',
    'u.deleted_at', 'u.is_anonymous', 'u.confirmed_at', 'u.banned_until',
    's.id=$1::uuid', 's.user_id=$2::uuid']) {
    assert.ok(ACTIVE_SESSION_SQL.includes(key), `missing ${key}`);
  }
});

test('private registry query filters active independently granted scopes', () => {
  for (const key of ['bl_directory_lab.publisher_operators',
    'bl_directory_lab.operator_action_scopes', 'sc.active', 'sc.revoked_at IS NULL',
    'sc.granted_by<>op.user_id', 'op.user_id=$1::uuid']) {
    assert.ok(OPERATOR_SCOPE_SQL.includes(key), `missing ${key}`);
  }
});

test('session ID and user ID are bound as parameters, not SQL-interpolated', async () => {
  const x = fakeDb({ rows: [{ allowed: true }] });
  assert.equal(await x.adapters.checkActiveSession({ userId: USER, sessionId: SESSION }), true);
  assert.deepEqual(x.calls[0].args, [SESSION, USER]);
  assert.equal(x.calls[0].sql, ACTIVE_SESSION_SQL);
  assert.ok(!x.calls[0].sql.includes(USER));
});

test('absent session row always denies', async () => {
  const x = fakeDb({ rows: [] });
  assert.equal(await x.adapters.checkActiveSession({ userId: USER, sessionId: SESSION }), false);
});

test('a false allowed result denies session even if row exists', async () => {
  const x = fakeDb({ rows: [{ allowed: false }] });
  assert.equal(await x.adapters.checkActiveSession({ userId: USER, sessionId: SESSION }), false);
});

test('string true must not be mistaken for PostgreSQL boolean true', async () => {
  const x = fakeDb({ rows: [{ allowed: 't' }] });
  assert.equal(await x.adapters.checkActiveSession({ userId: USER, sessionId: SESSION }), false);
});

test('database outage denies session without leaking errors', async () => {
  const x = fakeDb(new Error('auth.sessions unavailable'));
  assert.equal(await x.adapters.checkActiveSession({ userId: USER, sessionId: SESSION }), false);
});

test('malformed or injected identity never reaches SQL', async () => {
  const x = fakeDb({ rows: [{ allowed: true }] });
  assert.equal(await x.adapters.checkActiveSession({ userId: `${USER}' OR true --`, sessionId: SESSION }), false);
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: 'foo' }), null);
  assert.equal(x.calls.length, 0);
});

test('operator query returns only bound user, independently provisioned scope', async () => {
  const row = { user_id: USER, provisioned_by: ADMIN, country_code: 'IN',
    active: true, permissions: ['issue'] };
  const x = fakeDb({ rows: [row] });
  const result = await x.adapters.loadProvisionedOperator({ userId: USER });
  assert.deepEqual(result, row);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.permissions), true);
  assert.deepEqual(x.calls[0].args, [USER]);
  assert.equal(x.calls[0].sql, OPERATOR_SCOPE_SQL);
});

test('absent operator denies', async () => {
  const x = fakeDb({ rows: [] });
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
});

test('duplicate operator rows deny even if first row is valid', async () => {
  const row = { user_id: USER, provisioned_by: ADMIN, country_code: 'IN',
    active: true, permissions: ['issue'] };
  const x = fakeDb({ rows: [row, row] });
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
});

test('wrong operator identity fails closed', async () => {
  const x = fakeDb({ rows: [{ user_id: ADMIN, provisioned_by: USER,
    country_code: 'IN', active: true, permissions: ['issue'] }] });
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
});

test('malformed scope entry fails closed', async () => {
  const x = fakeDb({ rows: [{ user_id: USER, provisioned_by: ADMIN,
    country_code: 'IN', active: true, permissions: ['grant_admin'] }] });
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
});

test('broken or missing operator scope registry fails closed', async () => {
  const x = fakeDb(new Error('relation bl_directory_lab.operator_action_scopes does not exist'));
  assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
});

test('operator adapter does not accept unvalidated provisioner, active status or country', async () => {
  for (const row of [
    { user_id: USER, provisioned_by: 'not-uuid', country_code: 'IN', active: true, permissions: [] },
    { user_id: USER, provisioned_by: ADMIN, country_code: 'IN', active: 'true', permissions: [] },
    { user_id: USER, provisioned_by: ADMIN, country_code: 'ZZZ', active: true, permissions: [] },
  ]) {
    const x = fakeDb({ rows: [row] });
    assert.equal(await x.adapters.loadProvisionedOperator({ userId: USER }), null);
  }
});

test('trusted DB query adapter must be explicitly supplied', () => {
  assert.throws(() => createTrustedPgBackofficeAdapters({}), TypeError);
});

test('end-to-end isolated guard uses both PG lookups after mocked remote Auth succeeds', async () => {
  const rows = [];
  const db = { async query(sql, args) {
    rows.push({ sql, args });
    if (sql === ACTIVE_SESSION_SQL) return { rows: [{ allowed: true }] };
    if (sql === OPERATOR_SCOPE_SQL) return { rows: [{ user_id: USER, provisioned_by: ADMIN,
      active: true, country_code: 'IN', permissions: ['issue'] }] };
    throw new Error('Unexpected SQL');
  }};
  const backoffice = createTrustedPgBackofficeAdapters({ db });
  const payload = { iss: `${URL}/auth/v1`, aud: 'authenticated',
    role: 'authenticated', aal: 'aal2', is_anonymous: false, sub: USER,
    session_id: SESSION, iat: NOW - 60, exp: NOW + 300 };
  const token = `${Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.fakeSignature`;
  const gate = createOperatorAuthGate({ supabaseUrl: URL,
    publishableKey: 'sb_publishable_SYNTHETIC', now: () => NOW * 1000,
    fetchImpl: async () => ({ ok: true, json: async () => ({ id: USER }) }),
    ...backoffice });
  const result = await gate({ authorization: `Bearer ${token}`, operation: 'issue', countryCode: 'IN' });
  assert.deepEqual(result, { actorUserId: USER, sessionId: SESSION, operation: 'issue', countryCode: 'IN' });
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map(x => x.args), [[SESSION, USER], [USER]]);
});

test('end-to-end isolated guard still denies when session lookup fails', async () => {
  const backoffice = createTrustedPgBackofficeAdapters({ db: {
    query: async () => ({ rows: [{ allowed: false }] }),
  }});
  const payload = { iss: `${URL}/auth/v1`, aud: 'authenticated',
    role: 'authenticated', aal: 'aal2', is_anonymous: false, sub: USER,
    session_id: SESSION, iat: NOW - 60, exp: NOW + 300 };
  const token = `${Buffer.from('{"alg":"ES256"}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.fakeSignature`;
  const gate = createOperatorAuthGate({ supabaseUrl: URL,
    publishableKey: 'sb_publishable_SYNTHETIC', now: () => NOW * 1000,
    fetchImpl: async () => ({ ok: true, json: async () => ({ id: USER }) }),
    ...backoffice });
  await assert.rejects(() => gate({ authorization: `Bearer ${token}`,
    operation: 'issue' }), OperatorAuthDenied);
});
