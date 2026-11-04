# BharathLink — Consolidated Security & Release-Readiness Checkpoint

**Date:** 4 November 2026  
**Verdict:** **CI VERIFIED / RELEASE HOLD**  
**New checkpoint branch:** `bharathlink-consolidated-security-readiness-ci`  
**Final verified GitHub Actions:** https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41778877831  
**CI status:** SUCCESS — **5/5 jobs**. No APK assembled or distributed. No Supabase migration/deployment, key migration, or phone installation.

## Why this consolidation was necessary
The latest security development branch was **181 commits ahead of `main`** when inspected. `main` remained on commit `0ecbd7f45b22d5dcafca5ab36156d6097646c953`, a 25 October 2026 BharathMail date-boundary change. This is a **security staging lineage**, not a reconciled production app update. There were also two unrelated open UI fix PRs. **Do not blindly merge the complete security branch into `main`** or deploy it.

Instead of creating another numbered phase, this branch:
- Preserves all existing 7B–7I staged security work.
- Adds `.github/workflows/consolidated-security-readiness-ci.yml`, a single five-job cross-phase CI.
- Adds `docs/security-release-readiness.json`, a machine-readable fail-closed HOLD/next-action matrix.
- Adds `tests/consolidated-readiness-contract.test.mjs`, explicit assertions that CI success cannot imply Play Protect clearance, trusted first-device activation or production readiness.

## Exact consolidated CI evidence
Run: [#41778877831](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41778877831)

| Job | Verified evidence | Result |
|---|---|---|
| Offline-contract-and-release-hold | **88/88 Node.js** source, crypto, issuer and HTTP contract cases; **24/24 Python** signer-continuity and protected workflow cases; zero fail/skip | PASS |
| Native-source-compilation | Pinned V36HF TEST ZIP hash; isolated Phase 7A/B/C source setup; Gradle `:app:testDebugUnitTest`; **35/35 Android JUnit** tests, including 13 Phase 7C security cases, 0 failed/skipped | PASS |
| Postgres-edge-challenge | **7/7** actual Edge-source ↔ disposable PostgreSQL integrated tests and Phase 7B challenge/replay smoke | PASS |
| Postgres-existing-device-and-first-device-hold | First-device and first-verified-signer bypass denied, duplicate SQL races denied, legitimate synthetic second-device v2 atomic transaction exactly once | PASS |
| Postgres-issuer-revocation-governance | Synthetic P-256 signed review receipt, immutable issuer pin, competing governance intent, rotation and revocation automatic veto; zero first-device trust | PASS |

**One initial master CI issue was identified and fixed:** the Phase 7B SQL smoke inserted a previously consumed proof into the same disposable database *before* the Phase 7E HTTP test's exact count assertion. The workflow now runs that smoke **after** the HTTP scenario, preserving fixture isolation. The first combined run did not pass; the linked **final run did pass**. No production files or real databases were involved.

## Release blockers with required next action — none resolved by synthetic CI
1. **Google Play Protect:** Phase 7A APK displayed **Harmful app blocked** on the phone. Official appeal was submitted, but **no reversal confirmed**. Do not disable protection or install anyway. An independent APK security/reputation review and official decision is necessary.
2. **Original KeyPrep signing continuity:** Existing GitHub Actions debug signatures changed between builds. The installed APK's signing certificate and the private signing key required for a compatible update are not independently verified. Never uninstall/clear KeyPrep, overwrite its package, export AndroidKeyStore keys or ask for signing secrets in chat. Verify through an authorized signer custody and read-only ADB check when appropriate.
3. **Hosted OTP template and email delivery:** The Supabase TEST Magic Link email template must be inspected for `{{ .Token }}` and provider/rate-limit settings. Prior dashboard template content was not accessible; mark **NOT VERIFIED** rather than assuming OTP works.
4. **Real signed Android-to-server possession flow:** Existing Edge candidate release gate remains hard-disabled. The JUnit signer and synthetic HTTP tests do not prove a live user session and physical AndroidKeyStore key were verified together. Test only after Play Protect/signing clearance and security approval, keeping trust promotion OFF.
5. **Real identity issuer, two independent human reviewers and user consent:** Previous review signatures/identities are synthetic. A real authorized identity-proofing organization and governance/incident/dispute/retention contracts are not in place.
6. **Independent first-device approval:** Phase 7G/H are **review-only**, Phase 7I is a **HARD HOLD**, and no real first-device trust-approval transaction has been externally audited or deployed. A green source CI must never set `serverApproved`, `trustedDevice`, or `e2eeV2Ready` to true.
7. **Two actual Android phones / full app features:** End-to-end identity continuity, encrypted messaging, calling, email and UPI request verification require independent physical testing. These have not been established by the isolated crypto CI.
8. **External security and launch readiness:** Independent penetration testing, signing/distribution review, application privacy, abuse/fraud controls, independent logs, operational incident response and relevant compliance checks are still outstanding.

## Source versus live TEST boundary
- Branch is a source-only snapshot of staged SQL/Edge/native tests, **not** a production artifact or approved migration.
- Existing `bl20-candidate-possession`, `bl20-device-approval`, `bl20-device-approval-v2`, and `bl20-recovery-v1` Edge feature gates remain OFF in committed source.
- Phase 7F v2, 7G governance, 7H issuer pinning and 7I first-device HARD HOLD **are not installed in live Supabase**. Earlier read-only schema checks verified this; do not claim the live database benefits from these new triggers.
- `main` is untouched; no unrelated PR or user data was merged.
- The original installed KeyPrep and its non-exportable keys are untouched. No new Android APK was built or distributed by this consolidation workflow.
- **This is not an independent external security audit**. It is an internal source and isolated CI consolidation.

## Recommended work order
**Priority A:** Resolve official Play Protect and signer continuity, and read-only verify TEST OTP template. These are practical blockers to resuming controlled Android physical tests.  
**Priority B:** Real account-key challenge TEST after explicit security scope approval, with endpoint exposure narrowly bounded and first-device trust still OFF.  
**Priority C:** Real accountable identity issuer, consent, reviewer independence, immutable external logs and independent first-device transaction security review.  
**Priority D:** Controlled two-physical-phone E2EE/calling/messaging/email/payment trust regression, independent pen test, then separate production release decision.

**Do not** confuse CI "PASS" with overall app complete, an externally verified identity, a Play Protect-approved APK, or authorized public launch.

## Persistent handover and execution artifacts
- Consolidated workflow: `.github/workflows/consolidated-security-readiness-ci.yml`
- Fail-closed status model: `docs/security-release-readiness.json`
- Release guard tests: `tests/consolidated-readiness-contract.test.mjs`
- Verified test result: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41778877831

**Next meaningful milestone should be a resolved, independently verified external blocker—not another source-only security phase number.**
