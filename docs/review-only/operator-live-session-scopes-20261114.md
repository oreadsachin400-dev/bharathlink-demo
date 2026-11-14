# BharathLink — Live-Session and Operator-Scope DB Adapters (LAB ONLY)

**14 November 2026 | DRAFT / SECURITY HOLD | No TEST/PROD writes**

## Purpose and actual schema inspection

The previous review-only Auth gateway could authenticate a Supabase Bearer
token through `GET /auth/v1/user`, require `aal2` and reject mismatched
identity, but it deliberately required two independent backend adapters:
`checkActiveSession` and `loadProvisionedOperator`.

Official BharathLink-20 TEST Supabase catalog was inspected **read-only** on
14 November 2026. Its real `auth.sessions` contains `id`, `user_id`,
`aal` (`auth.aal_level`) and `not_after`; `auth.users` contains
`id`, `role`, `is_anonymous`, `confirmed_at`, `deleted_at` and
`banned_until`. Only **schema metadata** was read: no existing session IDs,
account details, passwords or tokens were returned.

## Implemented

1. `security/review-only/operator_backoffice_adapters.mjs`
   - `checkActiveSession` issues a strictly parameterized `SELECT EXISTS`
     against **both `auth.sessions` and `auth.users`**, binding the
     verified user ID and signed session ID to one record.
   - Requires `aal2`, a non-expired session when `not_after` is present,
     a confirmed non-anonymous/non-banned/non-deleted user with
     `role='authenticated'`. Missing rows, DB errors, ambiguous returns
     or malformed UUIDs deny.
   - `loadProvisionedOperator` returns only a current, independently
     provisioned publisher and the explicitly active action scopes from
     private `bl_directory_lab.operator_action_scopes`. No cached JWT
     `user_metadata`, `app_metadata` or request-supplied actor IDs are
     used to grant scope. Queries are static, parameterized, read-only.
   - Both adapters require a dedicated trusted **server-side PostgreSQL
     query connection** supplied by the eventual backoffice. They do not
     create a connection, carry credentials, perform mutations or expose
     data through browser-accessible Supabase RPCs.

2. `sql/review-only/operator_action_scopes_lab.sql`
   - Adds **private LAB-ONLY** per-operator `issue`/`revoke` grants.
     Scope owners cannot self-authorize, scope revocations are terminal,
     deletes are rejected and immutable grant/revoke events are recorded.
   - RLS enabled; `PUBLIC`, `anon`, `authenticated` and
     `service_role` have **no table grants**. No real operator has been
     provisioned; `bl_directory_lab` is absent from active TEST/PROD.

3. Contract tests
   - `tests/operator_backoffice_adapters.test.mjs`: 18 isolated Node
     tests with synthetic query results, including one end-to-end
     integration of the prior Auth gate with these two adapters.
   - `tests/operator_action_scope_contract.pgsql`: disposable PostgreSQL
     scope-grant/revoke, terminal-state, audit and ACL checks with a
     synthetic `auth.sessions`/`auth.users` shape.
   - `tests/run_operator_backoffice_pg_contract.mjs`: executes the
     **exact SQL strings exported by the Node adapter** against disposable
     PostgreSQL. Hard-fails outside the specifically named local CI
     database and runs AAL1, expired session, banned, anonymous, deleted,
     unconfirmed, mismatched identity and scoped-operator cases.

## Verified checks

[GitHub Actions #43618939369](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43618939369) completed **SUCCESS, zero errors**: **81 named PostgreSQL PASS lines** (62 previous + 7 private-scope contract + 12 exact-query PostgreSQL probes), plus **45 Node PASS tests** (27 prior Auth gateway + 18 new backoffice adapter), **126 total isolated checks**. The first two CI attempts had only synthetic fixture-ID expectation mismatches; after correction the complete suite succeeded.

## Release blockers

- This is still a local contract, **not** a production session-validation
  service: no verified user logged into TEST, no real MFA challenge, no real
  Auth token was submitted, and no actual issuer/revoker was hired,
  independently vetted or enrolled.
- The operator scope table has **not been created** in TEST or PROD.
  The existing TEST `auth.sessions` and `auth.users` objects are
  owned/secured by Supabase Auth; production access must be carefully
  restricted to a dedicated backoffice role with minimum column-level
  privileges, audited connection custody and no exposed Data API.
- `session_id` checks cover only available Auth session state; rapid
  revocation semantics, cross-service propagation, replay protection,
  operator MFA recovery and incident response still need a real
  integration and threat-model audit.
- Publishing remains **separate and disabled**. The session and scope
  gate issues no Verified badge, never changes organization status,
  never alters phone/email endpoints and does not integrate a real
  government/business registry verification provider.
- No Netlify, APK, GitHub branch merge, or TEST/PROD migration was
  requested or executed.

**RELEASE HOLD:** current work is a review-only backoffice building
block, not user-ready Verified Directory. A trusted deployment with
actual operator onboarding, role provisioning, session checks, separate
identity evidence and independent auditor approval is still required.

### Relevant official sources
- [Supabase sessions](https://supabase.com/docs/guides/auth/sessions)
- [Supabase JWT claims](https://supabase.com/docs/guides/auth/jwt-fields)
- [Supabase security: RLS and database roles](https://supabase.com/docs/guides/database/postgres/row-level-security)
