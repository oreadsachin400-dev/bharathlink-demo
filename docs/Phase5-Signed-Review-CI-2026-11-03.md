# BharathLink — Phase 5: Signed Independent-Recovery Review Integration (TEST ONLY)
3 November 2026 | Security regression and protocol hardening | NOT DEPLOYED

## Scope completed
- Extracted the genuine ECDSA P-256 RAW (64-byte) signature verifier into `supabase/functions/bl20-recovery-v1/review-crypto.mjs`, reused by the staged disabled Edge Function and the exact same Node.js CI checks.
- Issuer public key is loaded from the restricted DB context, never trusted from the incoming Android/client request. Strict 16-line domain-separated review payload validation, canonical P-256 JWK checks, two distinct reviewers, timestamp boundaries, raw/base64url signature shape, and SHA-256 over the actual signed content.
- Added `sql/staged/TEST-recovery-review-issuer-pin-v2.sql`: the receipt now pins the server-selected issuer public key fingerprint and locks issuer/challenge/case through the same database transaction. A concurrent issuer key rotation/revocation can no longer cause a previously verified signature to be consumed against a changed signing key.
- Revoked service_role EXECUTE on the original unpinned five-argument receipt RPC and granted service_role EXECUTE on the six-argument key-pinned RPC only. Existing anon/authenticated grants remain denied. No live DB migration is executed.
- Added a GitHub Actions integration test with disposable PostgreSQL 17, disposable synthetic Supabase users/sessions, and genuine randomly generated P-256 issuer keypairs. The run uses the real DB-built signed payload; malformed/placeholder signature fails, real signed proof passes the same verifier used by the disabled Edge Function, and two concurrent database consumers race to claim one REVIEW RECEIPT (exactly one succeeds).
- The test signer private key exists only in CI process memory; never stored in GitHub artifacts/secrets or transmitted.

## Safety contract
- Real independent identity-verification authority: **NOT CONFIGURED**.
- Production issuer pins, reviewer onboarding, legal retention/privacy controls: **NOT CONFIGURED**.
- Real remote Android enrollment: **NOT ENABLED**.
- Real device approval, `messaging_devices` INSERT/UPDATE, E2EE activation and original KeyPrep migration: **NOT IMPLEMENTED IN PHASE 5**.
- Existing installed KeyPrep app and nonexportable keys are untouched; original APK private signing key still missing. Do not uninstall or replace.
- `const RECOVERY_RELEASED = false` remains enforced before privileged API calls. Do not deploy/enable the Edge until independent audit and authority governance complete.
- Positive proof means `reviewReceiptStored:true`; status is *review-only* and all downstream trust fields remain FALSE. A device requires a distinct, separately reviewed authorization and cryptographic onboarding flow. CI synthetic issuer is never eligible outside test fixtures.
- Some legacy candidate and approval RPC functions are `SECURITY DEFINER`, so only protected Edge service-role credentials may call them; do not expose their functions to authenticated clients.
- In Phase 5 the old receipt function remains callable by the migration/database owner, who is already privileged. Service-role REST access is removed. Never treat a service role itself as an identity authority.
- All testing occurs in disposable CI infrastructure; no live Supabase project/database/Edge Functions/Android installation is altered.

## Next dependencies (not implied to be complete)
1. An independent legal identity-proofing/recovery organization, mutually agreed issuance policies, independently pinned issuer keys, key-rotation/revocation and reviewer-approval controls.
2. Complete server-side abuse-rate limits, case creation and independent evidence review; turn on only after threat modelling, compliance, privacy governance and separate two-person authorization controls.
3. Separate high-assurance **device activation** transaction after a successful proof, with key continuity and upgrade/downgrade refusal. Never turn a review receipt into trust automatically.
4. Isolated native TEST Android flow for a fresh package and fresh keys; ensure no installed KeyPrep data or signing certificate is overwritten. Then perform two physical-device tests with independently audited E2EE V2 keys.
5. Reconfirm live Supabase remains unchanged after this staged CI branch.

## Test entry points
- `node --test tests/phase5-recovery-issuer-crypto.test.mjs tests/independent-review.test.mjs`
- `node tests/phase5-real-signed-recovery-ci.mjs` after the disposable SQL fixtures are loaded.
- `bash tests/fixtures/phase5-recovery-crypto-concurrency.sh` after successful synthetic signature verification.
- GitHub workflow `phase5-real-issuer-crypto-tests.yml` also runs Deno syntax/typecheck for the disabled Edge.

Important: This tests actual **cryptographic review evidence** inside CI, not a true third-party person-identity assertion. All reviewers and issuers in tests are synthetic.
