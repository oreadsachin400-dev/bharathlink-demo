# BharathLink Phase 7J — first-device trust readiness

**5 November 2026 | Read-only TEST audit | STAGED only**

## Scope
Phase 7I prepared disposable PostgreSQL hard-stop guards and passed synthetic concurrency tests, but those SQL guards are not deployed to BharathLink-20-TEST. Phase 7J adds a read-only SQL inventory, an offline fail-closed risk classifier, adversarial tests and GitHub CI. No migration, Android APK, Supabase Function, Netlify deployment or production change.

## Live Supabase TEST evidence (read-only audit 2026-11-05 17:16 UTC)
Project: fsdusofbpwdrdvgexxyw.

| Control | Observation | Meaning |
| --- | --- | --- |
| Active device records | 8 | Historical device rows do not establish independent approval |
| Verified nonrevoked signer keys | 0 | No existing trusted approver |
| Legacy pairing trust anchors | 0 | No legacy first-device authority |
| Pending enrollment requests | 0 | Nothing currently pending approval |
| Phase 7I database hard-stop triggers | 0 | Staged protections not installed |
| Direct authenticated messaging-device INSERT RLS | Enabled; policy WITH CHECK false | Direct client registration currently denied; also inspect for additional permissive policies |
| Legacy v1 approval service-role RPC | Executable | Privileged legacy path exists; public Edge remains disabled |
| Deployed bl20-device-approval Edge | APPROVAL_FEATURE_RELEASED=false | Enrollment remains disabled |
| Deployed bl20-pairing-gate | pairingEnabled=false, registrationEnabled=false | Pairing remains disabled |
| Independent real issuer/reviewer authority | Not established | First device cannot be independently approved |
| Historic E2EE key recovery | Not established | Login cannot decrypt history without keys |

Edge flags were checked in the deployed function source, not inferred from staging. Inspection is not independent penetration testing.

## Release decision
**SECURITY_HOLD.** Never treat a login, OTP, directory profile or E2EE V2 registration as trusted-device approval. Do not seed fictitious signing anchors or reviewer identities, relax RLS, auto-generate replacement keys, silently revoke old keys, clear WebView IndexedDB, uninstall an existing Android package or merge staged security code into live systems without independent review.

The offline posture classifier **never** returns deviceEnrollmentAllowed=true or recoveryAllowed=true. Even a synthetic all-green snapshot returns INDEPENDENT_REVIEW_AND_SERVER_TRANSACTION_REQUIRED, because a read-only snapshot is not a cryptographic authorization.

## What is necessary before live recovery
1. Real identity authority with documented onboarding, two accountable independent human reviewers, signed issuer key custody, pinning, rotation, revocation and dispute process.
2. Fresh authenticated account binding, candidate signing and ECDH key possession proofs; server-selected nonce, expiry, audience, exact account, key and request binding; verifier checks signed issuer review evidence.
3. Independently audited atomic database authorization, nonce consumption, concurrent replay protection, immutable audit, RLS/service-role boundaries and reviewed rollback path.
4. Physical Android key continuity and signing-certificate checks. Validate original local keystore/IndexedDB without extracting private keys. Test both Sachin/Nidhi phones for forward/reverse E2EE after verified approval. Old history still needs compatible historic keys or an independently audited backup.
5. Review source-to-deploy provenance, security tests, and legal/provider requirements before any production release.

## Files and acceptance
- recovery-gate/live-trust-posture.mjs — offline non-authorizing classifier.
- sql/audit/TEST-first-device-trust-posture-READ-ONLY.sql — single-row aggregated DB inventory.
- tests/phase7j-trust-posture.test.mjs — missing/stale/tampered/fully-green snapshots, Edge, RLS and no-activation tests.
- .github/workflows/phase7j-trust-posture-ci.yml — offline only, no credentials or network writes.

The findings are a checkpoint, not working recovery or an installable application.