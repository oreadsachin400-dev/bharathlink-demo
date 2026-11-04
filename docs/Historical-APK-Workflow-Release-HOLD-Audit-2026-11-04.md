# BharathLink — Historical Debug APK Workflow Release Audit and HOLD

**4 November 2026 | GitHub Actions source control only | Play Protect warning unresolved**

## Final verified checkpoint

- Reviewed branch: `bharathlink-keyprep-installed-signer-audit-ci`.
- [GitHub Actions #41785468405](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41785468405) — **SUCCESS: 23/23 tests, 0 failures** (11 read-only installed-signer mock tests, 7 protected signer workflow tests, 5 historical APK workflow hold tests).
- Default `main` branch's Git tree `0ecbd7f45b22d5dcafca5ab36156d6097646c953` contained **zero** `.github/workflows/*.yml` files at audit time. This does not prove every unrelated branch or fork is protected.

## Source inspection result

Six old debug APK build-and-publish GitHub workflows on the current security branch still had jobs able to call Gradle `assembleDebug` and `actions/upload-artifact`. They now have a **job-level `if: false` HOLD**, rather than just a post-build APK checksum check. The historic source, signing inspection logic, packaging and workflow history are preserved, but the APK-producing job cannot execute or upload until an independently reviewed release change deliberately removes that HOLD.

| Workflow | Held job | Original GitHub branch also patched |
|---|---|---|
| `.github/workflows/build-android-test.yml` | `build` | `bharathlink-android-test-build` |
| `.github/workflows/build-v36hf-kotlin-test.yml` | `kotlin-v36hf-test` | `bharathlink-v36hf-kotlin-test` |
| `.github/workflows/build-v36hf-keyprep-test.yml` | `keyprep-test` | `bharathlink-device-keyprep-v1-test`; `bharathlink-signing-otp-preflight-v1-test` |
| `.github/workflows/build-phase6-offline-freshprep.yml` | `fresh-offline-android` | `bharathlink-phase6-offline-android-freshprep-v1-test` |
| `.github/workflows/build-signing-inspector.yml` | `offline-inspector` | `bharathlink-signing-inspector-v1-test` |
| `.github/workflows/phase6-offline-freshprep-android.yml` | `isolated-native-selftest` | `bharathlink-phase6-offline-android-freshprep-v1-test` |

Additionally:
- `.github/workflows/keyprep-protected-signing.yml` previously used a manual protected signing path; that job is already on explicit **`if: false`** in the original safe-signing branch and this security branch. Original signing secret references remain in protected GitHub environment expressions, but no secrets or keystore files are exposed in this audit.
- Earlier Phase 7A and standalone Auth Probe APK workflows have already been converted to **compile + JUnit only**, no APK artifact upload.
- Phase 7D/E workflows may upload **non-installable CI evidence logs**, not APKs. These were not disabled. Consolidated Android/crypto/PostgreSQL regression remains available through the separate compile-only/source-only workflow.

## New automated guard

`tests/test_historical_apk_workflow_hold.py` now:
1. Fails if any of the seven known protected or historical APK jobs is missing its job-level `if: false`.
2. Scans the reviewed `.github/workflows/*.yml` for actual `actions/upload-artifact` steps carrying APK output paths; any executable APK artifact publishing job fails.
3. Confirms Phase 7A and Auth Probe compile-only, no `assembleDebug` or APK upload.
4. Confirms protected signing configuration remains present but disabled.
5. Confirms release-readiness JSON is still **HOLD** and no phone-installed certificate has yet been verified.

The new guard is run within the existing [read-only installed-signer CI workflow](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41785468405). Its GitHub branch is review-only and never builds, installs or uploads an APK.

## What has NOT happened

- **No real phone was connected**. The actual installed KeyPrep v40 certificate has still not been observed; the 11 read-only ADB tests were mock-only.
- The matching original signing **private key** is not proven available by the archived public certificate fingerprint or this CI.
- **No Play Protect clearance** has been received/verified by this work. Prior Phase 7A harmful-app classification remains a release blocker; do not disable/bypass Play Protect.
- No APK was created, signed, uploaded or installed as a result of this audit. Existing historic artifact evidence and original KeyPrep AndroidKeyStore keys are untouched.
- No live Supabase, production deployment, first-device trusted enrollment or E2EE feature was modified or enabled.
- No guarantee is made for independently modified/forked branches outside the reviewed workflows. Other unknown hosting channels and any future security changes need a separate release audit.

## Next meaningful, non-repeated task

Only a **user-authorized read-only local phone check** can compare the *actually installed* KeyPrep's public APK signer to the archived fingerprint. Use `scripts/audit_installed_keyprep_signer.py` on a trusted laptop with official Android SDK tools and the original app left installed. The script and safe-use instructions are in [KeyPrep signer handover](https://github.com/oreadsachin400-dev/bharathlink-demo/blob/bharathlink-keyprep-installed-signer-audit-ci/docs/KeyPrep-Installed-Signer-Local-Audit-2026-11-04.md).

Even if the phone certificate matches, a compatible original signing private key, independent Play Protect resolution and real device authorization review are still separately required. **Do not deploy an APK or make a first-device trust grant.**
