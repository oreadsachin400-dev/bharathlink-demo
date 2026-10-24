# V39 live recovery integration gap audit — 2026-10-24

**Decision: SECURITY HOLD. No live recovery or enrollment cutover.**
Scope: source-reviewed V39 branch reference modules, not a deployed service or verified production environment.

## Evidence reviewed
- `v39_signed_authority_receipt_REFERENCE_NOT_DEPLOYED.mjs`: verifies pinned Ed25519 issuer signature, binding, expiry, and supplied revocation set. It does not issue receipts, fetch fresh revocations, or persist consumed receipts.
- `v39_independent_recovery_gate_REFERENCE_NOT_DEPLOYED.mjs`: even a valid signed receipt returns `allowed:false` / `ATOMIC_AUTHORITY_CONSUMPTION_REQUIRED`.
- `v39_recovery_atomic_receipt_DISPOSABLE_ONLY.sql`: rollback-only PostgreSQL challenge/receipt consumption demonstration, not the existing Supabase private schema or a deployed RPC.
- `v39_trusted_enrollment_composition_REFERENCE_NOT_DEPLOYED.mjs`: approved-device enrollment reference; explicitly excludes first-device bootstrap, recovery, and legacy RPC cutover.
- `approved_enrollment_handler_REFERENCE_NOT_DEPLOYED.mjs`: reference-only signed approver enrollment endpoint; not a recovery endpoint.

## Release-blocking gaps
1. **Authority contract**: choose and vet an independent identity verification authority, establish issuer signing key provenance, server-only trust config, revocation and key rotation, and explicit human review of identity and device ownership. Do not accept JWT/OTP/self-asserted approval as sufficient.
2. **Recovery receipt creation**: build a trusted-server endpoint that obtains verified authority evidence, signs canonical receipt transcript, and persists server-generated challenge and issuer receipt. No receipt signing secret in browser, Android APK or repo.
3. **Durable atomic consume**: implement in reviewed TEST-only private schema with explicit DB transaction/locks, unique receipt/challenge consumption, race/replay and crash-retry tests, and no direct anon/authenticated EXECUTE.
4. **Key compatibility**: prove the existing active device's actual signing algorithm and possession with a fresh challenge. Legacy raw 32-byte Ed25519 versus P-256 fallback must be identified; no guessed conversion, copied keys, or automatic registration.
5. **Bootstrap / lost-device policy**: define independently authorized first-device and total-device-loss procedures, rate limits, audit and delay/notification. No OTP-only bypass.
6. **Legacy RPC**: existing `register_e2ee_v2_device(uuid,text,text)` bypass must remain under security hold until secure replacement, migration and recovery are proven, then be revoked in a coordinated audited cutover.
7. **Android acceptance**: WebView local E2EE key storage and session continuity, two physical phones, cross-device signing approval, recovery, denied/replay cases, background calls and notifications.
8. **Deployment evidence**: validate TEST project schema and credentials through read-only preflight; perform reviewed migration on TEST only after gates 1–6. Production is out of scope.

## Safe next implementation sequence
A. Design signed authority protocol and key management with independent provider (no provider selected).
B. Implement isolated trusted-server receipt issuance and durable challenge storage, with mocks and negative tests.
C. Implement transactional TEST-only recovery consumption plus authorization state machine, separately from ordinary enrollment.
D. Prove legacy key compatibility and device ownership, test first-device and lost-phone paths.
E. Complete two-phone Android acceptance; review cutover and rollback before any deployment.

**CI green means reference tests pass; it is not evidence of operational identity verification, deployed recovery or a safe APK.**
