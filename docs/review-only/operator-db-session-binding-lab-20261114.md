# BharathLink — Operator Session Identity Binding (REVIEW ONLY)

**14 Nov 2026 | DRAFT / SECURITY HOLD | NOT DEPLOYABLE**

## Purpose

The preceding badge state machine correctly enforced independent review, but its
internal `p_actor uuid` parameter was supplied by a privileged caller. If a
backoffice accidentally passed a caller-controlled value, a compromised service
could impersonate an issuer or revoker. This was a genuine unfinished trust
boundary. A SQL check that the supplied UUID merely belongs to a publisher
registry does not authenticate the actor.

This **disposable PostgreSQL 16 proof** explores one way to remove the actor
parameter: bind a deliberately separate authenticated database login to a
privately provisioned operator UUID. This is **not Supabase Auth integration**,
not a real institutional verifier, and not a recommended ready-to-use production
operator API.

## Isolated prototype

- `sql/review-only/operator_session_binding_lab.sql`
  - Private `bl_directory_lab.db_operator_bindings` with an initially empty
    operator-login registry. Requires another recorded provisioner; no client
    table grants. A binding can be disabled without deleting the audit subject.
  - Two private wrapper functions:
    `issue_verified_entity_bound_lab_v2(request_id, valid_until)` and
    `revoke_verified_entity_bound_lab_v2(entity_id, reason)`.
    **Neither function accepts `p_actor`**.
  - Each wrapper derives actor from PostgreSQL `session_user` joined to an
    active, scoped, admin-provisioned internal mapping. It rejects logins that
    do not exist, are disabled or are privileged/superuser/CREATEROLE/BYPASSRLS.
  - Calls existing validated badge issue/revoke functions using this mapped
    identity; independent reviewer, evidence, expiry and revoker constraints
    still apply. Underlying v1 privileged functions are not granted to operators.
  - The wrappers necessarily use `SECURITY DEFINER` (a deliberately restricted
    **test-only** privileged bridge) with an empty `search_path` and qualified
    table/function names. Both default to **REVOKE EXECUTE FROM PUBLIC, anon,
    authenticated, service_role**. There are no client-facing or exposed-schema
    RPCs, external keys or real user credentials.

- `tests/operator_session_binding_contract.pgsql`
  - Creates **synthetic** issuer, revoker and outsider SQL login roles in CI.
  - Gives the issuer only the issue wrapper, revoker only the revoke wrapper;
    neither may read or alter the binding table or directly execute v1.
  - Simulates distinct authenticated PostgreSQL sessions with a local CI
    superuser running `SET SESSION AUTHORIZATION`. Confirms absent or disabled
    bindings fail closed.
  - Forges `request.jwt.claim.sub` and `request.jwt.claim.role` in test
    sessions; verifies immutable event and issued/revoked-by UUID still match
    the **DB login binding**, not the claim.
  - Confirms independent revocation, permissions and rapid deprovisioning.

## Threat boundary / limits

1. In PostgreSQL, `session_user` reflects the original database login even
   while a `SECURITY DEFINER` function runs as its owner; a privileged
   superuser can change this identity. **This design only protects ordinary
   isolated per-operator SQL roles**, not a superuser, DBA, shared DB credential
   or compromised connection broker.
2. A typical Supabase web/Edge Function uses shared `authenticated` or
   `service_role` database roles through a pool. That is **not a distinct
   per-operator session**, and this candidate must **not** be reused to
   trust a pooled `session_user`. It has no real `auth.uid()` or auth session
   reconciliation. The synthetic JWT checks do not constitute JWT validation.
3. Production requires a dedicated, off-client backoffice that verifies the
   *real* signed Supabase/OIDC session against the identity provider, checks
   strong MFA and recent session validity, checks admin-controlled operator
   provisioning/role scope, binds the actor inside the trusted service, and
   executes a narrowly privileged audited operation. Never trust
   `user_metadata`, request-supplied UUIDs, unverified headers or
   client-exposed service keys.
4. The `SECURITY DEFINER` wrappers can bypass RLS by design. A production
   replacement needs an independent security audit, hardened function
   ownership/grants and full official TEST trigger/RLS/role parity. Role
   provisioning/deprovisioning and separation-of-duties audit are still a
   synthetic lab procedure, not an actual operational system.
5. Authority attestation hashes and reviewer UUIDs remain **fabricated**.
   No outside government/company source was queried or authenticated; no
   verified legal identity or official endpoint has been issued.
6. In CI all writes are confined to an ephemeral PostgreSQL container.
   Nothing was installed in BharathLink TEST or PROD; no migration, Netlify
   deployment, APK, E2EE key or real user data was touched.

## Verification

[GitHub Actions #43607843214](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43607843214) completed **SUCCESS with 62 named PASS log lines and no errors**: 53 previous directory/reviewer/badge/trigger/quota checks plus **9 new operator-binding checks**. The simulated sessions included an unbound outsider, disabled issuer/revoker, forged JWT subject and role, scoped grants, correct immutable audit identities, and instant deprovisioning.

## Release decision

**HOLD / DO NOT MERGE OR DEPLOY.** The exercise proves only that scoped
PostgreSQL login-derived actors can eliminate one spoofable function argument
in an isolated threat model. Real account authentication, operator hiring/
vetting/provisioning, registered-source verification, live permissions and
Android integration remain blocked.
