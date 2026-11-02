# BharathLink — Offline KeyPrep Signing Recovery Audit (2 Nov 2026)

## Findings
- The original KeyPrep-only artifact from GitHub Actions run **41413699189** is available under artifact ID **13126507761**, with ZIP SHA-256 `61617dbd716697d872d928a90ea97f24427a9d66924fcfeddbcee0e4a7fa09e5` as recorded in immutable CI job logs.
- It contains an APK and public signing metadata; no Android private signing key can be derived from an APK or public certificate.
- Archived KeyPrep-only certificate SHA-256: `df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475`.
- Original package: `com.bharathlink.app.test.keypreponly`, original versionCode `40`.
- A later debug build produced a different certificate and correctly failed the pre-distribution gate (run **41448636377**, no artifact).
- Current repository branch contains no keystore/key-export files; original private key has **not** been recovered.
- A green CI build does not constitute proof of which APK is installed on the physical Android phone.

## Read-only phone verification
- This branch builds an **optional, disposable, one-screen offline signing inspector** under **a different package** `com.bharathlink.app.test.signingaudit`.
- It only reads `PackageManager.GET_SIGNING_CERTIFICATES` for the exact KeyPrep-only package using Android package visibility `<queries>`.
- It compares current APK certificate SHA-256, exact package and versionCode with the archived public metadata. It does **not** access AndroidKeyStore, encrypted preferences, network, Supabase, payments or user accounts.
- No updates, uninstall, key migration or device-trust/enrollment mutations occur. Code/unit build and APK static permission checks required.
- On phone, a positive result **INSTALLED_SIGNER_MATCHES_ARCHIVED_APK_ONLY** establishes installed binary certificate continuity **only**; still no private signing key or authorisation for app update.
- A negative result is **not** a reason to delete or reinstall KeyPrep. It requires investigation of exact package and installed version.

## Release policy
- Original private signing key recovery is still BLOCKED. AndroidKeyStore app private keys are unrelated to APK-signing keys.
- No in-place KeyPrep update may be shipped until both secure recovery of the original signing private key and physical device certificate verification.
- Do NOT share signing keystore, API keys, OTPs or passwords in ChatGPT/GitHub.
- Existing KeyPrep and standalone AuthProbe must remain unchanged.
