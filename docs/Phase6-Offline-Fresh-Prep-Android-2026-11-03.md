# BharathLink Phase 6 — Fresh Android Key Preparation OFFLINE TEST
3 November 2026 | Separate native Android 12+ diagnostic app | TEST / DISPOSABLE only

## Why this is separate
- The existing physical Android KeyPrep package `com.bharathlink.app.test.keypreponly` has non-exportable app-private keys.
- Its APK certificate matched the archived versionCode 40 APK, but the original matching APK signing private key has **not** been recovered; a new in-place update may destroy access to the original AndroidKeystore keys.
- Previous AUTH PROBE email OTP succeeded, but authenticated user UUID did not match the original manually entered account label.
- Phase 5 server review and issuer P-256 cryptographic tests passed in **disposable** GitHub CI. No independent real-world identity authority exists, and no trust enrollment is approved.

## What Phase 6 adds
A new, isolated debug-signed package `com.bharathlink.app.test.freshprep` which can be installed alongside KeyPrep and AuthProbe. It has a single native Activity and requests **zero Android permissions**; no INTERNET, calls, notifications, camera, microphone, contacts, SMS, files, providers, services or WebView. Android `allowBackup=false`. Minimum Android API 31 because AndroidKeystore `PURPOSE_AGREE_KEY` is required.

Explicit button `CREATE DISPOSABLE TEST KEYS`: generates one signing P-256 private key (SHA256withECDSA) and one ECDH P-256 private key in this app's separate AndroidKeyStore. No keys generate on launch. Never delete/overwrite aliases; partial generation fails closed. Stores only a random disposable test device UUID in app-private preferences. Keys never export. The app never accepts account UUIDs or OTP and never talks to Supabase.

Explicit button `RUN LOCAL CRYPTO SELF-TEST`: creates a locally random one-minute, domain-separated sample payload `BHARATHLINK_FRESH_DEVICE_OFFLINE_SELFTEST_V1`. Checks public-key coordinate SHA-256 canonical fingerprints, P-256 ECDSA sign/verify and tampered payload rejection, plus P-256 ECDH shared-secret agreement against an ephemeral software keypair in RAM. The temporary derived shared secrets are zeroed after comparison. All operations are **local** and do not prove identity, remote device authentication, hardware-backed isolation, server challenge correctness or E2EE deployment.

Status explicitly ends with `serverApproved: false`, `trustedDevice: false`, `e2eeV2Ready: false`, `NO BACKEND OR SECOND PHONE TEST PERFORMED`.

## Critical boundaries
- This is **not** a production Android app, a production device enrollment or a trusted device.
- Debug-built APK signing may change on a future GitHub runner; keys in the disposable isolated package are **not** migration/production keys. Never try to import them into old KeyPrep, re-label them to an authenticated account or use them as cryptographic trust evidence.
- Existing KeyPrep, authenticated account, TEST Supabase SQL/Edge and DEMO/production are not touched by this CI build. Never uninstall, reset, clear data or update the existing KeyPrep app for this test.
- AndroidKeyStore key generation and ECDH must be physically tested on Android 12+; passing Kotlin unit tests and compiler builds alone is insufficient to claim physical hardware support or a two-phone E2EE PASS.
- The test app creates a *local software peer* only to exercise ECDH; it does not communicate between real phones.
- Real first-device activation and E2EE remain blocked until an independently governed identity authority, issuer root, abuse/privacy review, server challenge lifecycle, separate audited device approval, fresh Auth session checks, and an authorized multi-phone E2EE protocol exist.

## CI
- The build starts from the SHA-256-pinned reviewed V36HF SOURCE-READY ZIP, removes all original Java/Kotlin/WebView code in a temporary directory, drops AndroidX dependencies and creates a minimal manifest.
- `OfflineProofPolicyTest.kt` covers domain separation, malformed IDs, wrong key fingerprints, replay/expiry bounds, non-enrollment classification and payload tampering.
- GitHub CI compiles/executes JUnit, validates exact unique app ID/version, verifies APK signature, checks installed artifact manifest has zero requested/declared permissions, and publishes only the separate debug TEST APK.
- No backend migration, Edge deployment, user account writes, device approval or original APK update is performed.
