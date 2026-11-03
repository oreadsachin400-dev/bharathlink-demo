# BharathLink Phase 6 — Isolated Android Fresh P-256 Self-Test
3 November 2026 | TEST build | No existing KeyPrep mutation | No backend/device approval

## Why this separate Android package exists
The existing physical Android KeyPrep-only package `com.bharathlink.app.test.keypreponly`, versionCode 40, has local non-exportable keys in its AndroidKeystore; its original private APK signing key is still missing. An app with a different package cannot access those keys, and an APK signed by a different developer key cannot safely update KeyPrep.
The prior standalone AUTH PROBE app only tested Supabase TEST email OTP, without key migration. Phase 5 real P-256 issuer signature checks passed in synthetic CI, but there is NO real independent identity authority or live approved device bootstrap.

## Phase 6 Android implementation
This branch adds a one-screen `BharathLink Fresh KeyPrep TEST` under a completely **new unique app ID**, `com.bharathlink.app.test.freshprep`.
- The app is intentionally **OFFLINE** and has **zero Android permissions**, including no INTERNET. The APK cannot send data to Supabase or any server.
- It does not have a sign-in screen, account binding or client-side verified identity.
- On pressing **CREATE DISPOSABLE TEST KEYS**, the app generates two NEW P-256 AndroidKeyStore keypairs under its own unique package: one ECDSA signing key and one ECDH agreement key, and stores a synthetic local device UUID. It never accesses or deletes the old KeyPrep keys.
- Keys are non-exportable AndroidKeyStore handles; their SHA-256 public JWK fingerprints are displayed after explicit local self-test. The signatures and ECDH raw shared secret are never exported.
- On pressing **RUN LOCAL CRYPTO SELF-TEST**, it signs a fresh, 60-second, domain-separated, LOCAL TEST ONLY challenge, verifies ECDSA P-256, verifies a deliberately tampered payload is rejected, and compares ECDH key agreement with an ephemeral in-memory peer. The peer is **not another phone**.
- **CHECK LOCAL STATUS** returns `LOCAL_KEYS_ONLY_NOT_VERIFIED` when both keys are present. This is not a trust signal or E2EE readiness.
- The app never outputs `approved=true`, never invokes any registration RPC, never uses API keys, JWTs, OTPs, `messaging_devices` writes, or any network permission. It does not update existing KeyPrep, AUTH PROBE or the real BharathLink app.

## Security interpretation
A local self-test PASS proves only that THIS package was able to sign and agree on a local secret using its test keys. It is **NOT** Supabase account authentication, external identity verification, externally issued server challenge, enrollment, a trusted device, real person KYC, or production-grade E2EE.

The APK is signed with the ephemeral GitHub Actions debug keystore. The identity is NOT stable across future CI runs. A future APK may not update it because the signing certificate could differ, so **do not use this package for persistent enrollment credentials or user data**. These keys are disposable diagnostics and SHOULD NOT be relied on for continuity or production.

## Test and release gates
GitHub workflow `.github/workflows/build-phase6-offline-freshprep.yml`:
1. Checks pinned V36HF source archive SHA-256.
2. Strips original Android source, dependencies, components and permissions in a disposable GitHub workspace.
3. Builds exactly one launcher with an independent app ID, local P-256 code, pure Kotlin JUnit policy tests and no network.
4. Performs APK package, version, activity, signing and merged-permission checks.
5. Uploads TEST APK artifact only after all checks pass. This is **not** a production or trusted device APK.

## Physical phone test procedure (only if final CI passes)
1. **Do not uninstall, reset, clear storage, or update existing KeyPrep and AUTH PROBE.**
2. Optionally install the fresh disposable APK alongside them.
3. Launch the new **BharathLink Fresh KeyPrep TEST** app, press **CREATE DISPOSABLE TEST KEYS** exactly once.
4. Press **RUN LOCAL CRYPTO SELF-TEST**, then **CHECK LOCAL STATUS**. Expected: LOCAL_CRYPTO_SELF_TEST_PASS, tamper DENIED, ECDH PASS, serverApproved:false, trustedDevice:false and e2eeV2Ready:false.
5. Send the status screen without sharing secrets. No OTP, private key or API credential should be shown or requested.
6. Do not infer the original app is recovered or the device is approved from the test results.

## Live TEST Supabase remains unchanged
Previous Phase 5 read-only verification: 8 existing active device rows, 0 new enrollment requests, 0 verified signer keys, no deployed recovery schema, `messaging_devices` INSERT `WITH CHECK(false)`.
Phase 6 CI must not deploy or mutate Supabase, demo or production.

## Still blocked
A real independently reviewed first-device identity authority, secure server release, controlled receipt-to-activation transaction, stable Android signing identity, native authenticated account/key binding and two independently enrolled physical devices with production E2EE remain pending. This phase intentionally does not claim those are complete.
