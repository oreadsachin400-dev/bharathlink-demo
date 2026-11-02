# BharathLink — TEST KeyPrep Signing Continuity & Email OTP Read-Only Audit
**2 November 2026 | No installed app/keys changed**

## What was checked
- Actual ZIP archive of **BharathLink V36HF KeyPrep ONLY TEST** that was downloaded from GitHub Actions:
  - Archive SHA-256: `61617dbd716697d872d928a90ea97f24427a9d66924fcfeddbcee0e4a7fa09e5`
  - Reported APK signing certificate SHA-256: `df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475`
  - Certificate subject: `C=US, O=Android, CN=Android Debug`
- Previous **KeyPrep TEST** separate build certificate SHA-256:
  `6d4e8cf80681b219e01af0da655d0d47b51c1a6fd9822becb1dc48ede9434eda`
- Older Kotlin/Diagnostic TEST builds also had different debug certificate fingerprints.
- This establishes **ephemeral/differing GitHub debug signing across runs**. The actual phone-installed package signature has not been independently read by ADB; earlier screenshots show the downloaded KeyPrep ONLY app launched successfully.

## Signing continuity rule (strict)
- Android in-place update requires the same app package identity and compatible signing identity.
- **Signing certificate fingerprint alone cannot sign an update; the original private signing key must be available through an appropriately protected signing environment.**
- GitHub-generated ephemeral runner debug keystores are not a safe update-signing strategy. We have no evidence the original signing private key is available for reuse.
- Do NOT ask the user to uninstall/clear data, regenerate keys, or overwrite the existing KeyPrep installation. Its AndroidKeyStore keys cannot be read by a different package.
- This repository branch adds `scripts/check_keyprep_signing.py`, tests, archived apksigner evidence and a fail-closed check directly **before** APK artifact upload in the future KeyPrep workflow.
- The preflight compares the new *apksigner* certificate SHA-256 with the archived KeyPrep ONLY value and rejects absent/mismatched/ambiguous signer reports. It cannot prove the installed phone certificate without separate on-device verification.
- Any compatibility-check failure must **block release**, even if Gradle compile/unit tests pass.

## Email OTP check
- The `BharathLink-20-TEST` Supabase project exists and is healthy; native client code uses the active TEST publishable API key, not the secret service-role key.
- Supabase official docs specify an email OTP requires the **Magic Link** email template to contain `{{ .Token }}`. The same API otherwise can send a magic link.
- Connected Supabase read-only project/database functions do **not** expose actual hosted Auth email template contents. **OTP template status: NOT VERIFIED.**
- No OTP emails were sent, no user account was created, and Auth settings were not changed in this audit.
- Future owner-only dashboard check: **Supabase TEST → Authentication → Email Templates → Magic Link**. Verify that it contains `{{ .Token }}`, check delivery provider & rate limits, and change template only after preview/approval. Do NOT enter or disclose real OTP to anyone.

## Actual CI enforcement evidence (2 November 2026)
- [Preflight negative-test run #41448482934](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41448482934): **SUCCESS**.
- [KeyPrep build run #41448636377](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41448636377): compilation passed but **signer gate correctly FAILED**, so the artifact upload step did NOT run. This is an intentional compatibility rejection, **not** a successful release.
- The old `bharathlink-device-keyprep-v1-test` build workflow was separately changed (commit `4635b1c`) to **compile-only with artifact uploads disabled** until a stable compatible signing identity is available. Previous already-downloaded APKs and phone data are unchanged.

## Tests and release status
- GitHub preflight workflow: `.github/workflows/keyprep-signing-gate.yml` — negative tests block wrong, missing, malformed and multi-signer digests; archive evidence checks.
- Current `bharathlink-native-auth-bind-v1-test` implementation remains compile-only, with no APK shipped. Real mobile OTP + key binding cannot be claimed until safe signing and template configuration are verified.
- Existing TEST candidate / trusted-device approval endpoints remain hard-disabled. Existing 8 active messaging devices, 0 enrollment requests, 0 candidate proofs, 0 verified signer trust anchors at last audit.
- **No DB schema/rows, production, DEMO, keys or installed Android packages were touched.**

## Next decision gate
1. Locate the original KeyPrep ONLY **private** APK signing key in an authorized, protected signing store, or acknowledge it was ephemeral/unrecoverable. Never ask anyone to send their private key through chat.
2. Independently compare installed package signer fingerprint on the same physical phone before any update (no uninstall). If the key is not recoverable, preserve the old app and design a separately authorized migration/new-package enrollment, rather than pretending keys can be transferred.
3. Read-only verify TEST Magic Link template `{{ .Token }}` and provider/rate-limit settings; don't send or share OTP without a concrete testing step.
4. Only after valid signing and configuration, physically test native account authentication and local P-256 matching. This still is NOT first-device identity verification or trusted-device approval.

**Verdict: Automated release safety gate implemented. Normal app update remains BLOCKED; hosted email OTP configuration remains UNVERIFIED.**
