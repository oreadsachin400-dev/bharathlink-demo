# BharathLink Phase 7C — Authenticated Challenge Exchange (Source-only TEST)

**Checkpoint:** 4 November 2026. This work is based on the verified Phase 7B source and security CI.

## Existing evidence
- Phase 6 Android Fresh KeyPrep: independent offline P-256 ECDSA/ECDH local self-tests PASS; keys persisted after relaunch.
- Phase 7A isolated Android OTP/key-binding APK: GitHub CI PASS, Android physical installation was **blocked by Google Play Protect** ("Harmful app blocked"). VirusTotal had no malicious vendor detections among reporting scanners; Google engine timed out. Play Protect appeal was **submitted**, **not approved/cleared**.
- Phase 7B: P-256 proof format, real ephemeral Postgres challenge expiry/atomic replay, native signer compile-only CI PASS. Existing candidate Edge release gate `FEATURE_RELEASED=false` remains hard-disabled. No real Android-to-server proof.
- Original KeyPrep and its private keys remain untouched.

## New Phase 7C files
- `android-phase7c/Phase7cProofCoordinator.kt`: one-shot authenticated session → server challenge → exact P-256 signature → server proof receipt. Authenticated subject is not user-entered; matching device, signed proof ID, signing JWK and canonical payload checked before any signing. Rechecks session/foreground/expiry between stages. Rejects any result with server-approved, trusted-device or E2EE-ready flags set.
- `android-phase7c/Phase7cProofCoordinatorTest.kt`: synthetic/mocked JUnit negative tests for account and device mismatch, changed public keys, expiration, tampered proof, background transitions, token changes, repeat submission, and forged server trust flags. Fake signatures here are format placeholders only, never cryptographic proof.
- `android-phase7c/Phase7cTestHttpsTransport.kt`: fixed HTTPS host `fsdusofbpwdrdvgexxyw.supabase.co`, only `functions/v1/bl20-candidate-possession`. Reject redirects, overlarge or non-JSON responses and unexpected authorization state. Uses public publishable API key plus ephemeral TEST bearer; no service-role/secret key in the app.
- `android-phase7c/Phase7cPreparedNativeFlow.kt`: source-only bridge from Phase 7A's temporary authenticated session and Phase 7B's isolated AndroidKeyStore signer to Phase 7C transport; runs off the Android main thread, invalidates bearer after one attempt.

## Critical hard gates
- No Phase 7A UI handler calls the Phase 7C bridge.
- No new APK is produced, distributed or installed.
- No edge function deployment or release-gate change.
- No migrations, Supabase writes, production RLS edits or device activation.
- No original KeyPrep private-key access, migration, replacement, or uninstall.
- Even a future valid possession receipt would **NOT** constitute independent human identity verification, device approval or live E2EE activation.

## Exit criteria / next tasks
1. CI `phase7c-authenticated-proof-contract-ci.yml` must pass **all** Android JUnit and source checks before calling this work a source-only PASS.
2. Independently evaluate Google Play Protect warning and signing/distribution practices. Do not bypass "Harmful app blocked." Submitted appeal alone does not clear it.
3. After classification clearance and explicit security approval, perform a narrowly scoped real Android-to-TEST Edge proof with a real account, new disposable keys, and hard-limited server exposure; do not silently flip the existing Edge gate. Confirm expected denial while disabled.
4. Separate independently authorized first-device identity bootstrap, device approval, and real two-phone E2EE testing remain HOLD.

## Source-control details
GitHub branch: `bharathlink-phase7c-authenticated-proof-contract-test`
Workflow: `.github/workflows/phase7c-authenticated-proof-contract-ci.yml`.

## Final verified CI checkpoint
- Final branch commit for source/tests: `0456a121765f88d6d394cc83e1690ed9d8276056`.
- GitHub Actions: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41698418947
- **CI PASS: 35 JUnit tests actually executed, 13 Phase 7C contract-security cases, 0 failures, 0 errors, 0 skipped.** APK output absent by explicit CI assertion.
- P-256 challenge payload now checks both **ECDH and signing public JWK SHA-256 hashes**, using the server's PostgreSQL `jsonb::text` canonical serialization. Exact synthetic vector was verified by a read-only query against Supabase-20-TEST: ECDH example hash `d4e14e99b1a297f7501be97a31db9647aabd90274d911f17fde34bdf14b75898`. This prevents signing challenges whose database-held EC keys do not equal the client's intended keys.
- Final TEST read-only state observed: 8 existing messaging device rows, 0 pending device enrollments, 0 verified signing keys, 0 candidate proofs.
- These are offline/mock-contract and compilation results only. Server Edge endpoint remains hard-disabled. **No Android installation approval, live backend possession proof, device trust, or full E2EE claim.**
