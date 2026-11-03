# BharathLink — Phase 3 Independent First-Device/Recovery Review Gate
3 November 2026 | TEST ONLY | Offline security module + synthetic cryptographic tests | NO DEPLOYMENT

## Verified starting state
Physical Android KeyPrep signing inspector matched installed com.bharathlink.app.test.keypreponly, versionCode 40, with archived certificate SHA-256 df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475.
The original Android APK private signing keystore has not been recovered. The public certificate cannot sign a new in-place APK.
Existing KeyPrep non-exportable AndroidKeyStore device keys must remain untouched. Do not uninstall, clear data, overwrite, or re-label the original app's local keys.

3 November 2026 read-only TEST Supabase audit: 8 active messaging devices, 0 enrollment requests, 0 non-revoked verified signing keys. messaging_devices INSERT RLS remains WITH CHECK false.
bl20-candidate-possession and bl20-device-approval Edge Functions remain hard-disabled; privileged DB RPCs are service_role-only.

## This code actually implements
recovery-gate/independent-review.mjs is an offline independent-recovery REVIEW-ELIGIBILITY proof validator with no network, SQL writes, database connection, or Android app dependencies.
It checks server-sourced authenticated session ID and user, an unexpired pending enrollment request and exact candidate device, both public-key fingerprint SHA-256 digests, consent and case linkage, two distinct independent reviewers, review evidence digest, and an ECDSA P-256 signature from an independently pinned issuer public key.
The signed payload domain is BHARATHLINK_INDEPENDENT_RECOVERY_REVIEW_V1, binding account, session, request, device, both key digests, review evidence, two reviewers, issuance, expiry and the non-approval decision.
A client-provided public key is not an eligible issuer. There is NO real issuer trust anchor configured today. Synthetic issuers in tests are not live or authoritative.
Even when all synthetic test evidence passes, result is REVIEW_ELIGIBLE_ONLY_NO_DEVICE_APPROVAL with deviceTrusted=false, e2eeReady=false and enrollmentCommitted=false.

## Critical trust boundaries
All inputs named trustedRequest, trustedAuth and trustedReview, the server time, and the issuer registry MUST be obtained from an authenticated server and integrity-protected database/configuration, NEVER from a mobile client's self-asserted JSON. The module alone cannot supply the trustworthy provenance of those inputs.
A signed review is not sufficient evidence of the real-world quality of identity checks. Before any activation, an organization must select and audit an independently authoritative issuer and define legal basis, evidence retention, appeal, review-conflict, revocation and privacy processes.

## Real enrollment missing steps
1. Define an actual independent high-assurance first-device identity/recovery authority, verified issuer trust root and protected two-person review workflow. OTP, prior APK signing certificate, client P-256 possession, existing device row, or self-declared account label are NOT enough.
2. Implement server-generated unpredictable nonce, short expiry, immutable account/request/candidate-key bindings and SINGLE-USE replay protection, enforced atomically using database row locks/unique constraints. This offline validator does NOT consume a nonce.
3. Validate fresh Supabase Auth user AND active session_id against auth.sessions for sensitive steps. Do not authorize based on stale JWT or user_metadata alone.
4. Review rate limiting, audit logs, external issuer key lifecycle, privacy and retention policy, and independent threat model.
5. After REAL independent first-device approval, a separately audited transactional path may create device records; it must be impossible to reuse existing approved-device RPC to bypass first-device checks.
6. Keep historical KeyPrep APK and private data untouched. If signing key is unrecoverable, use separately authorized fresh-device onboarding with newly generated keys, without pretending to have migrated non-extractable old keys.
7. Native account/key binding, separate E2EE V2 Ed25519/X25519 bootstrapping and encrypted two-phone validation remain pending.

## Checks
Run node --test tests/independent-review.test.mjs. The tests use real randomly generated synthetic P-256 ECDSA keys and negative cases for tampering, wrong issuer, account/session mismatch, expired/consumed requests, wrong fingerprints, invalid consent and malicious input.
GitHub CI checks candidate proof and device approval endpoints remain hard-disabled. No signed APK is built/uploaded by this workflow.
This is REVIEW-ONLY STAGING. No Supabase/DEMO/production/Android state is changed, and NO device trust/enrollment approval is granted.

## Phase 3 v1.1 tightening
The signed canonical review now binds an independently server-issued challengeId and candidateProofId. A separate, server-verified candidate P-256 possession record must be in possession_proven state and its public signing-key digest must match the pending candidate exactly. These fields MUST be joined from trusted DB state, not uploaded by a client. No challenge is consumed or approved by this offline module; future server activation still requires transactionally atomic nonce consumption and real independent identity authority.
