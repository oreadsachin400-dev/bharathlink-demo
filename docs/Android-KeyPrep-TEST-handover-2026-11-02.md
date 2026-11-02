# BharathLink — Android Local KeyPrep TEST | 2 November 2026

**Branch:** `bharathlink-device-keyprep-v1-test` (isolated from previous V36HF and backend approval branches)

**CI:** https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41409437925 — SUCCESS

## Implemented
- Native second Android launcher, **BharathLink KeyPrep TEST**, in independent debug package `com.bharathlink.app.test.keyprep`.
- Optional, explicit user action only: enter TEST account UUID **as unverified local label**, press **Prepare local P-256 keys**.
- Produces distinct AndroidKeyStore elliptic-curve P-256 signing key and P-256 key-agreement key; both private keys are non-exportable through this app's API.
- Persists random per-account device UUID in encrypted shared preferences after key generation and self-test.
- Read-only **Check local keys** shows public JWKs, device UUID and `serverApproved=false`, `e2eeV2Ready=false`.
- Rejects unsupported devices (pre-Android-12), invalid UUID, absent KeyStore key, inconsistent storage, and provider failures; never treats local key creation as authority.
- No connection between native local keys and WebView JavaScript bridge; no Supabase enrollment writes and no activation of the Device Approval v1 Edge Function.
- Compiler + existing JUnit tests and static security tests PASS; signed debug APK artifact uploaded and SHA-256 matched.

## Boundaries
- This release prepares P-256 enrollment primitives only; **it does not establish independent identity, attestation, or authorized first-device trust**.
- It does **not** create Ed25519/X25519 E2EE-v2 keys or enable calling, messaging, email or payments.
- The entered account UUID is not authenticated by this local-only utility; it cannot be used as proof of ownership.
- Physical-phone key creation, persistence through app restart, and local key failure handling must still be tested on actual Android hardware.
- Device-specific hardware security backing is not assumed. AndroidKeyStore isolation alone is not authoritative identity attestation.
- Debug APK is NOT production approved. The existing user's DIAG TEST app should remain installed because package IDs differ.
- APK **SHA-256:** `ebb18ff1428a76d2d97f0f88367d60bdb6066ae8125950de96f38adc11a793b6`

## Remaining release gates
1. Verified external first-device bootstrap or independently approved audited recovery workflow, with no automatic trust from login or local key generation.
2. Approver authenticity and user-initiated signing against server-selected, one-time canonical challenge; ensure status, ownership, revocation and expiry.
3. Server-side verifiable approval receipt and careful native key/device association; do not carry private keys across app packages.
4. Native/WebView authorization boundary and session binding review.
5. Real two-phone E2EE v2 key provisioning, encryption/decryption plus negative security tests.
6. Only after these gates, consider enabling the currently hard-disabled `bl20-device-approval` Edge Function in TEST.

## Live TEST backend checked after this build
- 8 active messaging devices.
- 0 enrollment requests.
- 0 verified signing keys.
- RLS INSERT `WITH CHECK false`.
- No database/schema changes made by Android KeyPrep work.

**Verdict:** Local native KeyPrep source and signed TEST APK compiled and verified. Physical device KeyPrep pending; first-device trust/bootstrap and messaging E2EE activation remain blocked.
