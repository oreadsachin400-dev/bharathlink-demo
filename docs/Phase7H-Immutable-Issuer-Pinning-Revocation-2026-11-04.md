# BharathLink Phase 7H — Immutable Issuer Key Pinning, Rotation/Revocation Audit

**Verified checkpoint: 4 November 2026 | STAGED CODE + DISPOSABLE CI ONLY | NOT DEPLOYED**

## GitHub source and test evidence
- Branch: `bharathlink-phase7h-issuer-pinning-revocation-ci`
- Workflow: `.github/workflows/phase7h-issuer-key-pin-ci.yml`
- Final verified [GitHub Actions run #41775926342](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41775926342): **SUCCESS, both CI jobs completed successfully**.
- Static contract: **7/7 Node.js tests PASS, 0 failed, 0 skipped**.
- Disposable PostgreSQL 17 + genuine synthetic P-256 review signature: **PASS**, including signed review receipt, exact key fingerprint, legacy v2 grant withdrawal in staged schema, concurrent v3 receipt consumption exactly once, late replay rejection, immutable historical evidence, cross-account/session rejection, stale key rejection, key rotation automatic governance veto, revocation, rejection of un-revocation, and zero first-device trust.
- One prior CI attempt failed because an older Phase 7G test fixture intentionally *un-revoked* an issuer after testing. This action is now forbidden by the Phase 7H policy. The workflow was corrected to use a Phase 7H-specific preflight instead of weakening revocation. The final verified run is the one cited above.

## Specific gap closed
Phase 5 `bl20_recovery_v1_review_consume_v2` checked an issuer key fingerprint **at receipt consumption time** but did **not** persist the actual issuer public JWK/fingerprint in a new immutable receipt record. Phase 7G governance had therefore only the issuer's current key fingerprint to compare, not a historical key snapshot created when the review was signed.

The new **staged-only** `sql/staged/TEST-recovery-review-immutable-issuer-pin-v3.sql` introduces:
1. Private, RLS-enabled `bl20_issuer_pin_v1_private.receipt_pins` keyed by challenge ID and unique case ID. It stores issuer ID, issuer public JWK, canonical P-256 key fingerprint, attestation digest and pin time in the **same PostgreSQL transaction** as the signed review receipt.
2. `public.bl20_recovery_v1_review_consume_v3` service-role-only RPC. It locks challenge, case and issuer, recomputes/compares issuer key fingerprint, calls the previously reviewed v2 review-only consume, verifies the resulting receipt and snapshots the issuer public key before transaction commit. It returns `deviceApproved=false`, `trustedDevice=false`, `e2eeV2Ready=false`.
3. Staged revocation of the old **v2** service-role receipt-consume grant. The **currently deployed** recovery Edge still calls v2 but is hard disabled. If the new migration were applied, its stale v2 call would also fail closed until separately reviewed.
4. An issuer-pin guard on Phase 7G `review_intents` before insertion. It requires the signed receipt's historical issuer JWK, fingerprint and attestation hash to match the still-active issuer registry key. Key substitution, missing pin and revocation cause rejection.
5. Append-only issuer change events recording `key_rotated`, `issuer_revoked` and `issuer_disabled`. Any real issuer key change or revocation in the database vetoes pending Phase 7G governance intents **inside the same database transaction** and writes an `intent_vetoed` audit record.
6. Historical pins and issuer event records reject ordinary SQL UPDATE and DELETE. A previously revoked issuer cannot be silently un-revoked, and an already-disabled issuer cannot be silently reapproved by changing a Boolean flag.

## New source/test files
- `sql/staged/TEST-recovery-review-immutable-issuer-pin-v3.sql`
- `tests/phase7h-concurrent-issuer-pin.mjs`
- `tests/fixtures/phase7h-pre-governance-denials.sql`
- `tests/fixtures/phase7h-governance-preflight.sql`
- `tests/fixtures/phase7h-rotation-revocation-audit.sql`
- `tests/phase7h-issuer-pinning-contract.test.mjs`
- `.github/workflows/phase7h-issuer-key-pin-ci.yml`

## Independent safety boundaries
- This produces an **issuer evidence pin**, NOT a first-device approval. Phase 7G `review_intents` remain in `governance_pending_review_only` or `governance_vetoed`. No `messaging_devices` or verified signing-key rows are inserted for an untrusted first-device account.
- The CI issuer, reviewers, signatures, Auth sessions and users are synthetic. Cryptographic P-256 test keys are generated in CI memory. This is not evidence of a contracted external verification authority or real human reviewer independence.
- The privileged database/migration owner can change table/trigger definitions or disable triggers. Thus ordinary SQL immutability is **not tamper-proof against superusers**: independent WORM logs, administrative separation, external attestation, monitoring and governance review remain needed.
- Actual approval must not be inferred from a review receipt, stored issuer pin, P-256 key possession or two reviewer UUIDs.
- Do not apply the staged migration to live TEST before security review and operational controls. Do not expose its private schema to apps or grant public/anonymous execution. No changed Edge Function or APK was built/deployed.
- Original KeyPrep installed app and nonexportable private keys remain untouched.
- **Google Play Protect "Harmful app blocked" classification is unresolved** in the available evidence; prior official appeal submission is not a reversal. Do not bypass the warning or advise an unsafe install.

## Live Supabase read-only checks after final CI
Project `fsdusofbpwdrdvgexxyw`:
- 8 historical `public.messaging_devices` rows; historical records are NOT independently verified trust anchors.
- 0 `messaging_device_signing_keys` records with non-null `verified_at`.
- 0 pending enrollment requests and 0 candidate proof rows.
- Phase 7H `bl20_issuer_pin_v1_private` schema **absent** in live TEST.
- Phase 7G `bl20_first_device_v1_private` schema also **absent** in live TEST.
- The new public review-consume v3 RPC **absent** in live TEST.
- The original live protected Edge gates remain disabled; staged v3 grants and immutable triggers are *not* live.

## Next open blockers
1. Independently audited real identity issuer organization, issuer key custody/rotation, consent/reviewer evidence, fraud/dispute handling and legally appropriate retention.
2. Independent security architecture and pen test of the final device-trust authorization transaction with separation of roles, session revocation/rate limiting and durable external audit.
3. Play Protect official classification clearance and safe Android signing/distribution; original installed KeyPrep signing continuity must not be broken.
4. Authorized, real Android-to-TEST cryptographic challenge and future two-physical-phone E2EE V2 tests, **only** after independent approvals.

**Phase 7H outcome:** verified staged issuer-key continuity and automatic revocation governance tests only. Real-world identity and first-device approval remain BLOCKED.
