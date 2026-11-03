# BharathLink Phase 4 — Server Recovery Challenge and Atomic Review-Receipt Gate
**3 November 2026 | STAGED CODE ONLY | TEST environment design | NO live deployment**

## Objective and strict limitations

This phase adds a synthetic-tested PostgreSQL **single-use recovery challenge and review receipt** with a deliberately non-operational Edge entrypoint. It does NOT approve a device or grant trust or E2EE access. The required independent identity authority and immutable, externally verified issuer key have not been appointed/audited. Neither email OTP, a matching APK certificate, a self-declared UUID, nor a P-256 private-key-possession signature is sufficient for first-device authorization.

The pre-existing KeyPrep Android APK (versionCode 40) stays untouched. Its installed signer certificate matches the archived APK, but its original private APK signing key remains unrecovered. No downgrade, reinstall, private-key export, app data clearing or silent migration is permitted.

## Files and artifacts
- `sql/staged/TEST-recovery-challenge-atomic-v1.sql`: isolated non-exposed schema with issuer registry (empty by default), challenge table, independent review case table, and receipt table. Four service_role-only functions. All tables RLS-enabled; no anon/authenticated data grants.
- `supabase/functions/bl20-recovery-v1/index.ts`: STAGED disabled endpoint. `RECOVERY_RELEASED=false` before service-role lookup or parsing. When independently audited in future, requires Supabase Auth validation, session claim bound to DB session, server-side issuer public key and signed context, and stores receipt only; it does not insert devices.
- `tests/fixtures/phase4-recovery-sessions.sql`, `tests/fixtures/phase4-recovery-fixture.sql`, `tests/fixtures/phase4-recovery-concurrency.sh`: synthetic-only disposable PostgreSQL data and double-submit race test.
- `.github/workflows/phase4-recovery-transaction-tests.yml`: GitHub CI uses Postgres 17 service and real synthetic Phase 3 P-256 cryptographic tests; no live credentials, deploy or APK output.

## Protocol boundary

1. Before challenge issuance, server must authenticate JWT via Supabase Auth `/auth/v1/user` and correlate JWT `session_id` with `auth.sessions`. Sensitive API calls must reject absent/revoked/timed-out sessions. Existing Auth session enforcement may have stricter time-box/inactivity rules than `not_after`, and those require server-side Auth support when enabled.
2. Service-role-only SQL checks a recent, already consumed candidate possession proof (`possession_proven`), exact user, device UUID and both candidate public-key JWKs against an unconsumed, unexpired enrollment request, and no existing verified trusted approver; serializes issuance per user by transaction advisory lock.
3. The challenge holds server-generated random UUID nonce, context-bound owner UUID, session, candidate proof ID, enrollment request ID, device ID and canonical SHA-256 digests of the two P-256 public keys; lifetime at most 5 minutes; owner rate-limited.
4. A separate independently audited identity reviewer process (not built and NOT configured) must establish genuine identity and two independent reviewer decisions with consent and bind the immutable case, issuer key and P-256 signed attestation. No endpoint to create a case/issuer is exposed to users. The SQL migration provisions **zero issuers**.
5. For an eligible case, Edge must verify P-256 ECDSA with the server-pinned issuer public key, NOT a client-provided key. Server recomputes payload and signature hashes. The database locks challenge, case, candidate, enrollment request, session and issuer and compares independently computed immutable DB hashes before an atomic single-use consume.
6. Successful consume only inserts `review_receipt_only` audit evidence in the isolated schema. It **never inserts/updates `public.messaging_devices`**, `public.messaging_device_signing_keys`, E2EE key tables, user verification flags or app data. A separate security-reviewed high-assurance device enrollment transaction is required in later phases.

## Critical safety caveats

- The disposable SQL positive test creates **synthetic approved issuer metadata and synthetic signature bytes**. It exercises database row-locks, hash binding, replay rejection and proof/authorization guards **only**; it is not an end-to-end real-world authority, and by itself does not validate issuer cryptography. The existing Node Phase 3 tests separately validate genuine P-256 signatures and malicious tampering.
- The DB `review_consume` RPC trusts that a service-only Edge caller completed issuer-signature verification; do not expose this RPC to public/authenticated roles, or treat direct service-role calls as proof. Review of credential isolation and key lifecycle is mandatory before enabling the Edge path.
- No issuer, case, challenge or receipt is created by this code on the actual Supabase TEST project because **the staged SQL is never applied there by CI**. Production and DEMO remain unchanged.
- Current first-device bootstrap and final approval are still **BLOCKED**. Future integration must include independently established verification authority, real nonce-and-signature end-to-end test, signed approval protocol, secure receipt verification on native Android, two real-phone E2EE tests, rate limiting/abuse detection and privacy/retention governance.
- Existing 8 TEST messaging device rows, 0 verified signer keys, and 0 enrollment requests are the last verified read-only database state. The new CI test data lives in ephemeral PostgreSQL only.

## Required negative checks

Unauthenticated/other-account/expired session, no independent issuer, incomplete P-256 possession, altered candidate or request keys, wrong owner, wrong challenge, missing/expired/revoked reviewer case, invalid reviewer independence or consent, invalid payload digest, wrong attestation digest, expired nonce, concurrent double consume, consumed replay and attempts to alter public device-trust rows must fail. Verification returns `deviceApproved=false`, `trustedDevice=false`, `e2eeV2Ready=false` on every non-error result.

## Next safe milestone
Have an independent identity-proofing issuer and governance rules audited; integrate receipt verification with the native app on an isolated NEW package and new keys, without touching installed KeyPrep. Keep **physical-APK signing recovery a separate blocker**.
