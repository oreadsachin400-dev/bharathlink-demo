# BharathLink — Installed KeyPrep Signer Read-Only Verification

**4 November 2026 | Local opt-in phone inspection helper + GitHub mocked CI | RELEASE HOLD**

## What was actually accomplished

- Added `scripts/audit_installed_keyprep_signer.py`, a minimal read-only ADB + `apksigner` + `aapt` tool.
- It looks for the exact previously reported physically installed **KeyPrep ONLY TEST** package `com.bharathlink.app.test.keypreponly`, archived original **versionCode 40**.
- It reads only the public installed **base.apk** using `adb shell pm path` and `adb pull` into a temporary folder, extracts the signing certificate and package manifest metadata, compares it to the archived original KeyPrep-only signer, and removes the local APK copy before finishing.
- Archived candidate signing certificate SHA-256: `df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475`.
- It rejects missing/unauthorized/multiple devices, unsafe package paths, APK retrieval failure, wrong signer, multiple signers, wrong package and changed versionCode. Never attempts an installer or Android data/private-key access.
- [GitHub synthetic mock test run #41784302917](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41784302917) **SUCCESS: 11/11 tests PASS**. This is not a genuine phone reading.

## How to run later on the user's trusted laptop (only with explicit phone access)

**These steps are optional; do not repeat APK installation or reset KeyPrep.**

1. Connect **the phone that already contains the original KeyPrep ONLY TEST app** with a trusted USB data cable. Use the official Android SDK Platform Tools and SDK Build Tools on a trusted computer.
2. For a one-time read-only check, authorize USB debugging through the Android system prompt. Do not disable Google Play Protect, root the phone, run an installer or share an OTP.
3. Download/open the reviewed GitHub branch `bharathlink-keyprep-installed-signer-audit-ci`; the script requires Python 3 and the official commands `adb`, `apksigner` and `aapt` on PATH. It does not need signing keys, GitHub secrets, Supabase credentials or internet access.
4. From the repository directory run:
   ```bash
   python3 scripts/audit_installed_keyprep_signer.py
   ```
5. **Only a matching output** `PHONE_APK_CERT_MATCHES_ARCHIVED_KEYPREP_V40` confirms *public certificate continuity with the historical archived APK*. This is not signing private-key recovery and does not authorize any new APK or update.
6. If the script returns `BLOCKED`, preserve the app and data. Do not uninstall, disable Play Protect, replace the package, export keys, or try `adb root`. Inspect the cause carefully before any next action. Once done, disconnect the cable and revoke temporary USB-debugging authorization if appropriate.

**No APK or user files are uploaded.** The script deliberately suppresses device serial from its report. Its temporary APK copy is deleted by the normal context manager before results are printed.

## Separate, independently unresolved signing gates

- The original KeyPrep *phone-installed* signer has **not** been verified in this conversation; CI tests use synthetic `adb` responses only.
- The archived certificate fingerprint does **not** prove that the matching *private signing key* still exists in a secure custodian or a GitHub Environment. There is no safe in-place APK update without compatible app signing key custody and the correct versionCode, even if the installed public certificate matches.
- Google Play Protect identified a later **Phase7A** APK as **Harmful app blocked**. Earlier appeal submission does not establish a favorable decision. No Play Protect bypass, `Install anyway` advice, or Play Protect disabling is acceptable.
- The manual protected KeyPrep APK-signing/upload workflow has been placed on **explicit job-level HOLD** (`if: false`) in both the original safe-signing and consolidation branches while these gates remain unresolved. The protected signing configuration is preserved for a future independently reviewed change but **cannot run as-is**.
- Several other historical Android test-APK workflow files still reference debug assembly and upload. Their existence must not be confused with release authorization; do not manually run or install their outputs until reviewed. This change specifically closes the original KeyPrep signing and Phase7A/Auth Probe distribution routes.
- No Supabase database/Auth/Edge Function changes were made; original AndroidKeyStore material untouched.

## Operational next steps / report interpretation

| Independent gate | Current verified status | Meaning |
| --- | --- | --- |
| Archived KeyPrep certificate fingerprint | **Verified** from historical GitHub apksigner evidence | Expected public certificate only |
| Local audit script security + negative tests | **PASS** mocked CI | Procedure prepared, not performed on a real phone |
| Actually installed KeyPrep certificate | **NOT CHECKED** | Requires phone attached to trusted laptop |
| Compatible original private signing key custody | **UNVERIFIED** | Do not build or sign an update |
| Official Play Protect disposition | **UNKNOWN / BLOCKED** | No new APK install |
| Real account-to-original-key binding and first-device trust | **NOT TESTED / HARD HOLD** | OTP history cannot substitute for trust |

**Bottom line:** The next real progress requires an authorized read-only measurement on the existing Android phone and independent release-signing/Play Protect evidence; another synthetic CI phase alone cannot resolve those physical gates.
