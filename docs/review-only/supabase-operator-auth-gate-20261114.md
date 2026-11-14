# BharathLink — Supabase Auth Operator Gate (REVIEW ONLY)

**14 November 2026 | DRAFT / SECURITY HOLD | NO DEPLOYMENT**

## What changed

The earlier PostgreSQL proof tied a private issuer/revoker to a distinct
database login. It is not compatible with a shared pooled Supabase
`authenticated` or `service_role` connection as a per-person identity
mechanism. The next safe boundary must authenticate **the human's actual
Supabase Auth session** in a trusted server, not accept a caller-supplied
`p_actor`, operator name, email or JWT `user_metadata`.

This review-only, dependency-free Node module is a **server authorization
gate**, not a new public API route and not a badge publication function.

Files:
- `security/review-only/operator_auth_gate.mjs`
- `tests/operator_auth_gate.test.mjs`
- `.github/workflows/verified-directory-contract.yml`

## Implemented security boundary

1. Accepts only a bounded Bearer JWT; rejects extra request keys including
   caller-supplied actor IDs.
2. Checks token structure, correct official project issuer, expected
   authenticated audience/role, `aal2` (Supabase MFA), signed subject and
   session ID, non-anonymous status, issue/expiry time and a conservative
   one-hour maximum JWT lifetime. These preliminary payload checks **do
   not** establish cryptographic authenticity on their own.
3. Uses a **real HTTPS adapter** to the configured Supabase Auth
   `GET /auth/v1/user` endpoint with the **same token**, a project
   publishable key and a timeout. Only the Auth server can confirm the
   token's authenticity; a decoded JWT alone is never sufficient.
4. Requires a separate, trusted `checkActiveSession(userId, sessionId)`
   implementation to confirm session was not revoked/disabled and a
   separate, trusted `loadProvisionedOperator(userId)` implementation
   that reads a private, administrator-maintained operator registry.
5. Demands exact Auth user/sub match, active operator,
   independent provisioner, country scope and explicit issue/revoke
   permission. Never relies on `user_metadata`, `app_metadata` or
   a request `p_actor` to grant a Verified badge.
6. Returns only a frozen *authorization context* with the bound actor
   and session. **No SQL, badge issuance, revocation or endpoint change
   is executed by this gate**. All denied cases use one generic error.

## Tests and how to interpret them

The Node test suite runs entirely offline with a **mock Supabase Auth
response and mock privileged adapters**. All JWTs are fabricated
synthetic strings and **have not been cryptographically signed**.
The suite verifies the guard's decision logic, HTTP request formatting,
and that a forged JWT cannot succeed when the Auth adapter rejects it.
It does **not** prove that real Supabase credentials, real MFA or a
production database are correctly connected.

Covered cases: valid AAL2/mock session, remote rejection and outage,
identity mismatch, AAL1, expiry and long expiry, future issuance,
wrong issuer/audience/role, anonymous user, absent session, revocation
and session-registry outage, inactive or self-provisioned operator,
wrong operator ID, revoked operator, country/permission mismatch,
operator-store failure, injected `p_actor`, invalid bearer/operation,
and missing backend adapters.

## Verification result

[Isolated GitHub Actions #43616543424](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43616543424) completed **SUCCESS**. The same workflow recorded **62 previous PostgreSQL PASS checks plus 27 new Node tests PASS (89 total)**, with no errors. All Auth responses, users, sessions and operator records were synthetic; no live Supabase auth requests or TEST/PROD database writes occurred.

## Critical missing integrations — RELEASE BLOCKED

- **Real identity-provider test:** no access token was sent to actual
  TEST Supabase Auth, and no real operator with MFA was provisioned.
  The user's existing app 2FA PIN is not automatically a Supabase
  `aal2` session; operator enrollment and dedicated MFA are needed.
- **Authoritative session checking:** build a strictly private
  `auth.sessions` lookup by session ID and user ID, with revoked
  sessions denied. The required `checkActiveSession` adapter is currently
  **unimplemented** beyond synthetic tests.
- **Approved operator registry:** only a two-person vetted and audited
  administrative onboarding process may provision issuer/revoker rights.
  The required `loadProvisionedOperator` adapter is also
  **unimplemented** outside tests.
- **Publication integration:** the private lab badge functions still
  expect a privileged executor; do NOT grant direct browser/mobile
  EXECUTE access or expose a `service_role` key. A dedicated,
  independently audited, least-privileged backoffice operation must
  consume this newly authenticated actor with immutable attribution,
  second-person separation, scoped evidence and a short transaction.
- **Authoritative verification:** there is still no live government or
  organizational registry connector, authenticated registry signature,
  operator vetting program or endpoint evidence verification.
- **Operational security:** configure throttling, secret custody, MFA
  recovery, audit retention, policy testing, live code-review and
  session-revocation latency before any TEST rollout.

The module has **no externally reachable endpoint** and neither this
prototype nor the preceding lab has been deployed to BharathLink TEST
or PROD. GitHub PR #30 remains DRAFT / SECURITY HOLD.

### References

- [Supabase JWT claims reference](https://supabase.com/docs/guides/auth/jwt-fields)
- [Supabase MFA](https://supabase.com/docs/guides/auth/auth-mfa)
- [Supabase user sessions](https://supabase.com/docs/guides/auth/sessions)
- [Supabase server-side JWT verification](https://supabase.com/docs/reference/javascript/auth-getclaims)
