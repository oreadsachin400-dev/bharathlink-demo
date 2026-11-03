# BharathLink Phase 7E — End-to-End Edge HTTP + PostgreSQL Candidate Proof (Offline CI)

**Checkpoint:** 4 November 2026 | **Actual CI SUCCESS** | **No deploy, APK, or activation**

## Scope and verified evidence
- GitHub branch: `bharathlink-phase7e-http-postgres-integration-ci`
- Workflow: `.github/workflows/phase7e-edge-postgres-integration-ci.yml`
- [Verified GitHub Actions run](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41702423994) — **SUCCESS**, 7/7 Node test cases PASS, 0 failed, 0 skipped.
- Integrates the **actual** Edge source from `supabase/functions/bl20-candidate-possession/index.ts` (temporary runner copy only) with **actual** PostgreSQL 17 `bl20_candidate_proof_start/context/finish` functions in a disposable CI database.
- The JavaScript test generates synthetic EC P-256 signing and ECDH keypairs, obtains the genuine SQL-created short-lived canonical challenge, signs the exact payload in Android-compatible DER ECDSA format, and sends it through the real Edge implementation's crypto verification before the actual DB atomic consumption.
- Integration rejects invalid synthetic auth token, forged body `userId` override, other account's finish, incorrect signing key, expired DB challenge, malformed JWK and duplicate/replayed submissions. Two simultaneous finish requests from separate PostgreSQL connections were tested: exactly one succeeds.
- Successful receipt states **possessionProven=true, serverApproved=false, trustedDevice=false, e2eeV2Ready=false**. No devices inserted.
- All privileged REST and Supabase Auth responses are mocked and constrained to a synthetic hostname. No live network or real bearer JWT, and no secrets or production signing keys.

## Release and trust gates
- The committed and deployed candidate Edge source stays hard-disabled: `const FEATURE_RELEASED=false;`
- The device approval Edge source stays `const APPROVAL_FEATURE_RELEASED = false;`
- The independent recovery Edge stays `const RECOVERY_RELEASED = false;`
- Test-only enablement is applied **only to a temporary copy** inside GitHub Actions process memory/file system, destroyed after the CI test. **Do not enable live endpoint** based on this result.
- The TEST Supabase project was checked **read-only** after the run: 8 preexisting `messaging_devices` records, 0 pending enrollment requests, 0 verified signing keys, 0 candidate proofs. Production/TEST database and Edge functions were not modified.
- Original KeyPrep, E2EE private keys and installed apps were untouched. No fresh APK was created or installed.
- **Google Play Protect harmful-app classification is unresolved.** A prior appeal was submitted; no approval/reversal is confirmed. Never advise bypassing Play Protect or force-installing Phase 7A.

## Remaining blockers
1. Obtain official Play Protect warning clearance or resolve classification via security review and the formal process; evaluate stable signing and package distribution. The previous APK's VirusTotal reporting was not proof of safety.
2. Only after clearance and explicit security review: run actual authorized Android-to-TEST Supabase challenge with a user JWT and disposable keypair, while still preventing any device trust promotion.
3. Obtain independent identity issuer and evidence/reviewer governance, and approve a **separate high-assurance first-device enrollment**. Synthetic issuer/review tests do not constitute real identity.
4. Recover original APK signing continuity or establish secure user-consented migration; do not uninstall, overwrite or clear original KeyPrep data.
5. End-to-end two-phone E2EE requires separate physical checks and independent release gates.

## What Phase 7E does NOT prove
- Real phone installation or Android Keystore interoperability against the live service
- A real person's verified identity, an authorized enrollment, live device trust, or successful two-phone E2EE
- Google Play Protect clearance or malware safety assurance

**Next safe development focus:** audited device-trust transition contracts and release gates, without touching live enrollment.
