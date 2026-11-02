# BharathLink — Safe Android Signing Recovery & Email OTP Handover
**2 November 2026 | TEST Only | Status: CODE + SECURITY PREFLIGHT PASS, RELEASE BLOCKED**

## 1. Why this phase exists
The physically tested KeyPrep ONLY APK generated P-256 signing and ECDH keys in its Android application sandbox. AndroidKeyStore private keys are not exportable through this app. An in-place package update requires compatible signing identity and a higher version code. Earlier GitHub Actions builders generated different debug certificates, so their APKs must not be used as updates.

**Archived expected KeyPrep-only APK certificate SHA-256:**
`df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475`

**Expected package ID:** `com.bharathlink.app.test.keypreponly`

**Minimum later update version code:** `41` (original was `40`).

The expected APK signature is based on the previously distributed archive; the phone-installed certificate is not independently verified with device tooling.

## 2. Code implemented
- `scripts/check_keyprep_signing.py`: existing pinned certificate verifier.
- `scripts/check_keyprep_release.py`: requires that same certificate, exact package ID and strictly newer version code from real `apksigner verify` and `aapt dump badging` output.
- `tests/test_keyprep_release.py`: mismatching/absent certificates, wrong package IDs, downgrade versions and malformed signer metadata are all rejected.
- `.github/workflows/stable-signing-preflight.yml` and `tests/test_protected_signing_workflow.py`: negative tests; inspect that protected signing is manual-only and requires the protected key secrets.
- `.github/workflows/keyprep-protected-signing.yml`: manual `workflow_dispatch` only; locked to feature branch and `keyprep-signing` GitHub Environment, read-only repository permission, no PR triggers.
- The protected workflow verifies reviewed source, prepares compile-only existing-package v41 native authenticated TEST, builds/units tests, signs only from protected environment secrets, verifies the resulting APK's actual certificate + app ID + version, then uploads a 7-day TEST artifact.
- It requires **the original recovered, compatible private signing key** (protected `BHARATHLINK_KEYPREP_KEYSTORE_B64`, `BHARATHLINK_KEYPREP_STORE_PASSWORD`, `BHARATHLINK_KEYPREP_KEY_PASSWORD`, `BHARATHLINK_KEYPREP_KEY_ALIAS`). If unavailable, the workflow stops before signing or uploading. Never put those values into repository files, the conversation or screenshots. Do not synthesize a replacement key and pretend it matches the old certificate.
- Existing previous KeyPrep build branch has artifact uploads disabled until continuity is recovered.

## 3. Verified automated results
- [Signing and protected workflow negative tests #41452372617](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41452372617): **SUCCESS**.
- Earlier preflight #41451996652: **SUCCESS**.
- Earlier mismatched signing build #41448636377 correctly **FAILED the upload gate** after compilation; no incompatible APK was distributed by that run.
- Old KeyPrep compile-only branch #41448917921: **SUCCESS, zero artifacts**.
- These are **static/CI security tests**, **not** proof of a recoverable original private signing key, signed production build, physical phone update, or actual native OTP login.
- No private keystore files exist in the scanned feature branch's committed tree.

## 4. Email OTP configuration
Supabase documentation: passwordless email OTP requires `{{ .Token }}` in the shared **Magic Link** email template. Existing link flow can be preserved using `{{ .ConfirmationURL }}`; template modification must be reviewed as it affects existing login behavior.

- Reviewed example only: `docs/TEST-Email-OTP-Dual-Mode-Template-REVIEW-ONLY.md`.
- Supabase project's hosted Magic Link template content is **not exposed by available connected read-only Supabase tools**; current config remains **UNVERIFIED**.
- No SMS/email OTP was sent; no template, SMTP, or authentication settings were changed.
- Owner dashboard verification path: TEST project `fsdusofbpwdrdvgexxyw` → Authentication → Email Templates → Magic Link. If a numeric OTP already appears, do not change anything. Otherwise, review and preserve the current link and add `{{ .Token }}` in an approved TEST-only change.

## 5. Actual release blockers
1. Recover original matching **private** signing keystore through a legitimate controlled source and independently verify the installed app's certificate; **without it, there is no safe in-place update**.
2. If key cannot be recovered, preserve old app and its keys. A future NEW package means independent new local keys, separately authorized bootstrap and no automatic trust inheritance. Do NOT claim old keys were migrated.
3. Confirm real TEST OTP template and delivery, before native phone login-to-local-key proof.
4. First-device identity verification and trusted approval remain disabled; email OTP + P-256 possession do not confer governmental identity authority.
5. Two-phone E2EE-v2 work remains pending until real device approval and independently verified setup.

## 6. Safe instructions
- **No user action now:** leave the physically verified KeyPrep ONLY application installed.
- Do not clear application storage, uninstall, reinstall, or regenerate P-256 keys.
- Do not push private keystores or real OTPs to GitHub or this chat.
- No released APK is currently ready for safe in-place update.

**Verdict: secure signing release pipeline fully staged and CI tested, actual signed update BLOCKED until the original compatible signing identity is recoverable.**
