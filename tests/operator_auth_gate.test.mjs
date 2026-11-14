import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOperatorAuthGate, createSupabaseUserVerifier, OperatorAuthDenied } from '../security/review-only/operator_auth_gate.mjs';

const URL = 'https://fsdusofbpwdrdvgexxyw.supabase.co';
const USER = '11111111-1111-4111-8111-111111111111';
const OTHER = '33333333-3333-4333-8333-333333333333';
const PROVISIONER = '44444444-4444-4444-8444-444444444444';
const SESSION = '22222222-2222-4222-8222-222222222222';
const NOW = 1_800_000_000;

function fakeJwt(overrides = {}) {
  const h = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'ES256' })).toString('base64url');
  const payload = { iss: `${URL}/auth/v1`, aud: 'authenticated',
    role: 'authenticated', aal: 'aal2', is_anonymous: false,
    sub: USER, session_id: SESSION, iat: NOW - 90, exp: NOW + 900,
    ...overrides };
  return `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.fakeSignature`;
}

function makeHarness({ claims = {}, remoteUser = { id: USER }, remoteStatus = 200,
  remoteError = false, sessionActive = true, operator = {}, operation = 'issue',
  requestExtra = {}, sessionError = false, operatorError = false } = {}) {
  const token = fakeJwt(claims);
  const calls = { auth: [], session: [], operator: [] };
  const gate = createOperatorAuthGate({
    supabaseUrl: URL,
    publishableKey: 'sb_publishable_SYNTHETIC_NO_SECRET',
    now: () => NOW * 1000,
    fetchImpl: async (endpoint, init) => {
      calls.auth.push({ endpoint, init });
      if (remoteError) throw new Error('network error that must not leak');
      return { ok: remoteStatus === 200, status: remoteStatus,
        json: async () => remoteUser };
    },
    checkActiveSession: async (input) => {
      calls.session.push(input);
      if (sessionError) throw new Error('private session database unavailable');
      return sessionActive;
    },
    loadProvisionedOperator: async (input) => {
      calls.operator.push(input);
      if (operatorError) throw new Error('private operator database unavailable');
      return { user_id: USER, provisioned_by: PROVISIONER,
        country_code: 'IN', active: true, permissions: ['issue', 'revoke'],
        ...operator };
    },
  });
  const req = { authorization: `Bearer ${token}`, operation, countryCode: 'IN', ...requestExtra };
  return { gate, req, token, calls };
}

async function mustDeny(input) {
  const { gate, req } = makeHarness(input);
  await assert.rejects(() => gate(req), err => err instanceof OperatorAuthDenied
    && err.code === 'OPERATOR_AUTH_DENIED' && err.status === 403);
}

test('a valid remote-authenticated AAL2 session and provisioned issuer returns a bound actor, not a badge', async () => {
  const { gate, req, token, calls } = makeHarness();
  const result = await gate(req);
  assert.deepEqual(result, { actorUserId: USER, sessionId: SESSION,
    operation: 'issue', countryCode: 'IN' });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(calls.auth[0].endpoint, `${URL}/auth/v1/user`);
  assert.equal(calls.auth[0].init.headers.Authorization, `Bearer ${token}`);
  assert.equal(calls.auth[0].init.headers.apikey, 'sb_publishable_SYNTHETIC_NO_SECRET');
  assert.deepEqual(calls.session[0], { userId: USER, sessionId: SESSION });
  assert.deepEqual(calls.operator[0], { userId: USER });
});

test('remote Supabase Auth rejection stops all operator authorization', async () => {
  const { gate, req, calls } = makeHarness({ remoteStatus: 401 });
  await assert.rejects(() => gate(req), OperatorAuthDenied);
  assert.equal(calls.session.length, 0);
  assert.equal(calls.operator.length, 0);
});

test('remote network outage also fails closed with generic public error', async () => {
  await mustDeny({ remoteError: true });
});

test('token subject must match the user confirmed by remote Auth', async () => {
  await mustDeny({ claims: { sub: OTHER } });
});

test('Supabase MFA aal1 is insufficient for trust publication', async () => {
  await mustDeny({ claims: { aal: 'aal1' } });
});

test('expired JWT fails before using the remote provider', async () => {
  const { gate, req, calls } = makeHarness({ claims: { exp: NOW - 2 } });
  await assert.rejects(() => gate(req), OperatorAuthDenied);
  assert.equal(calls.auth.length, 0);
});

test('overlong one-hour issuer lifetime is rejected', async () => {
  await mustDeny({ claims: { iat: NOW - 90, exp: NOW + 7200 } });
});

test('future issued-at time is rejected', async () => {
  await mustDeny({ claims: { iat: NOW + 120 } });
});

test('wrong Supabase issuer/project is rejected', async () => {
  await mustDeny({ claims: { iss: 'https://different.supabase.co/auth/v1' } });
});

test('wrong token audience is rejected', async () => {
  await mustDeny({ claims: { aud: 'anon' } });
});

test('a service_role token cannot act as a human reviewer', async () => {
  await mustDeny({ claims: { role: 'service_role' } });
});

test('anonymous accounts cannot publish', async () => {
  await mustDeny({ claims: { is_anonymous: true } });
});

test('MFA token missing signed session_id cannot authorize', async () => {
  await mustDeny({ claims: { session_id: null } });
});

test('revoked or missing server-side Auth session fails closed', async () => {
  await mustDeny({ sessionActive: false });
});

test('session registry outage denies access', async () => {
  await mustDeny({ sessionError: true });
});

test('inactive operator cannot issue despite valid Auth and MFA', async () => {
  await mustDeny({ operator: { active: false } });
});

test('operator self-provisioning is rejected', async () => {
  await mustDeny({ operator: { provisioned_by: USER } });
});

test('operator user_id mismatch is rejected', async () => {
  await mustDeny({ operator: { user_id: OTHER } });
});

test('operator revoked_at requires fresh independent reauthorization', async () => {
  await mustDeny({ operator: { revoked_at: '2026-11-14T00:00:00Z' } });
});

test('issuer cannot revoke unless explicitly granted that operation', async () => {
  await mustDeny({ operation: 'revoke', operator: { permissions: ['issue'] } });
});

test('operator without required country scope is denied', async () => {
  await mustDeny({ operator: { country_code: 'US' } });
});

test('operator lookup failure is a denial, never a fallback to JWT app_metadata', async () => {
  await mustDeny({ operatorError: true,
    claims: { app_metadata: { role: 'super_admin' }, user_metadata: { admin: true } } });
});

test('client-supplied actor UUID is rejected before any remote lookup', async () => {
  const { gate, req, calls } = makeHarness({ requestExtra: { p_actor: OTHER } });
  await assert.rejects(() => gate(req), OperatorAuthDenied);
  assert.equal(calls.auth.length, 0);
});

test('missing bearer and malformed bearer are denied', async () => {
  const { gate, req } = makeHarness();
  await assert.rejects(() => gate({ ...req, authorization: 'Bearer malformed' }), OperatorAuthDenied);
  await assert.rejects(() => gate({ ...req, authorization: '' }), OperatorAuthDenied);
});

test('unknown operation is never forwarded to a privileged publisher', async () => {
  await mustDeny({ operation: 'grant_admin' });
});

test('required trusted session and operator adapters cannot be omitted', () => {
  assert.throws(() => createOperatorAuthGate({ supabaseUrl: URL,
    publishableKey: 'sb_publishable_SYNTHETIC_NO_SECRET' }), TypeError);
});

test('server Auth verifier refuses non-HTTPS and URL credential injection', () => {
  assert.throws(() => createSupabaseUserVerifier({ supabaseUrl: 'http://example.com',
    publishableKey: 'key' }), TypeError);
  assert.throws(() => createSupabaseUserVerifier({ supabaseUrl: 'https://user:pass@example.com',
    publishableKey: 'key' }), TypeError);
});
