# BharathLink Phase 7I — First-Device Trust Authorization HARD HOLD

**4 November 2026 | Staged SQL + disposable PostgreSQL 17 GitHub CI | NOT DEPLOYED**

## Final verified GitHub evidence
- Branch: `bharathlink-phase7i-first-device-hard-stop-ci`
- Workflow: `.github/workflows/phase7i-first-device-hard-stop-ci.yml`
- [Verified CI run #41777819300](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41777819300) — **2/2 jobs SUCCESS**.
- **6/6 Node security-contract tests executed**, zero fail or skip.
- Disposable PostgreSQL tests: first-device direct privileged INSERT denied; first verified signer on a historical unverified device denied; first-device attempt under revoked signer denied; account/device ECDH and signing-key rebinding denied; verified timestamp rewrite denied; silent device/key unrevocation denied; **both** simultaneous first-device INSERT attempts denied; no first verified signing key created on synthetic unverified account.
- Regression: existing synthetic previously verified account can obtain **one additional device** via the Phase 7F *candidate-proof-gated* v2 RPC. Two simultaneous v2 approval commits result in exactly one approval and exactly one proof/device audit link; replay is denied.

## Why this security boundary exists
Phase 7F additional-device approval v2 and Phase 7G/H signed first-device review governance are separate concerns. Even if a protected Edge handler is hard disabled, a privileged database owner or an accidental legacy SQL registration path can still affect the underlying `public.messaging_devices` and `public.messaging_device_signing_keys` persistence tables. The Phase 7I **HARD HOLD** adds fail-closed database triggers so a *first trusted signer* cannot be bootstrapped while there is no independent real-world approval authority.

## Added source
- `sql/staged/TEST-first-device-hard-stop-v1.sql`: private `bl20_first_device_hold_private` schema with `SECURITY INVOKER` trigger functions; `anon/authenticated/service_role` denied direct function execution. No public HTTP endpoint.
- Device INSERT boundary: locks account row, requires at least one distinct verified and nonrevoked signer + nonrevoked device with trusted `verification_method`; both relevant rows locked against concurrent revocation. If absent: reject `42501` before insertion.
- Device UPDATE boundary: prohibits silent account ID rebind, ECDH public key swap, algorithm change or revoked-device reactivation.
- Signing-key INSERT/verification boundary: account- and device-owner check, requires a **different** preexisting verified signer to bootstrap a newly verified signing key. Historical-but-unverified devices cannot mint their own first trusted signer. Revoked signer reactivation, signing public-key swap, verification-method change, account rebind and verified-at rewriting denied.
- Enables RLS defense-in-depth for `public.messaging_device_signing_keys` **in disposable CI only**.
- `tests/fixtures/phase7i-historical-unverified-device.sql`: one synthetic historical device without any verified signer, inserted **before** HOLD trigger install.
- `tests/fixtures/phase7i-hard-stop-denials.sql`: direct privileged SQL negative cases and checks that no rejected operation persists a trust row.
- `tests/phase7i-racing-first-device.mjs`: concurrent independent database connection race; both candidate INSERTs denied.
- `tests/phase7i-first-device-hold-contract.test.mjs`: source constraints, no trust-enabling API or public role grants, old issuer pinning and disabled Edge gates.
- `.github/workflows/phase7i-first-device-hard-stop-ci.yml`: all work on an ephemeral PostgreSQL service, no deploy, APK, GitHub release artifact or remote credential.

## Internal threat-model assessment — NOT an independent penetration test

| Potential attack or mistake | Status from Phase 7I tests | Unresolved safeguard |
| --- | --- | --- |
| Privileged SQL creates a first registered device with no prior verified signer | **Blocked in disposable Postgres** | DB owner can still alter/disable triggers; external admin governance needed |
| Privileged SQL adds a first *verified* signing key to a historical unverified account | **Blocked** | Future independently audited first-device bootstrap requires a separate reviewed trust transaction |
| Two concurrent first-device SQL INSERTs race | **Both blocked** | Reassess lock ordering and database latency under real load |
| Unrevoking a signing key or device silently | **Blocked** | Formal signed revocation/recovery process still required |
| Rebinding a verified signing/ECDH key or device to another account | **Blocked** | Key rotation/recovery procedure not yet integrated with operational authority |
| Accidental change breaks legitimate additional-device flow | **Existing v2 synthetic regression PASS** | Physical Android and authenticated TEST backend verification still missing |
| A malicious privileged database owner disables triggers or updates security tables | **Not prevented** | Separation of duties, independent log, restricted admin credential custody and external security review required |
| A malicious operator issues fabricated "audited_recovery" evidence | **First verified signer blocked under HOLD** | Human reviewer identity, issuer organization due diligence and KYC/evidence standard not established |
| Play Protect harmful-app classification | **Unresolved** | Official review, distribution signing audit and safe remediation, no bypass |

## Hard limits and deployment state
- No legitimate first-device authorization implementation is supplied here; the new trigger is a **temporary hard stop** that makes *all* first-device trust INSERTs impossible through ordinary SQL.
- No real issuer, independent accredited verifier, consent governance, hardware-backed server authority, external auditor, or actual first-device trusted state has been established. Passing synthetic CI is not human identity proof or regulatory approval.
- Existing `bl20-device-approval-v2`, `bl20-recovery-v1` and `bl20-candidate-possession` Edge release gates remain hard disabled.
- No live Supabase migration was applied. Read-only live schema check confirmed **`bl20_first_device_hold_private` absent**, and prior staged `bl20_issuer_pin_v1_private` / `bl20_first_device_v1_private` also absent.
- A separate read-only query for current device/signer/proof **counts was blocked by safety checks** in this turn. Thus latest exact live counts are **not freshly verified**; the previous Phase 7H checkpoint had 8 historical device records and zero verified signing keys, pending enrollments and candidate proofs.
- No new APK or Google Play Protect bypass; official harmful-app warning still not confirmed resolved. Original KeyPrep Android Keystore and signing continuity untouched.
- Historic **legacy v1 service RPC may still exist in live TEST** because Phase 7F–7I staged migrations were not deployed. Protected live Edge remains disabled. Do not assume staged grant revocations are already live.
- Trigger-only guards are not equivalent to enforcing cryptographic ECDSA approval inside Postgres. The protected Edge must independently verify signatures; an internal high-privilege bypass is still possible if the DB role can change schema.

## Release blockers / actual next actions
1. Real accountable identity issuer with policy for issuing evidence, key custody, rotation and revocation; two **human** independent authorized reviewers with segregation of duties, fraud/dispute and retention controls.
2. Design and externally review a **separate first-device approval transaction** that atomically consumes cryptographically verified issuer review + fresh candidate proof and enforces consent, session `auth.sessions` validity, account and key bindings, independent approvals, rate limits, replay protection, audit and safe revocation. Any future first-device enablement must replace the HARD HOLD under a reviewed migration—not toggle an environment flag.
3. Independent penetration test / security audit; test privilege escalation, public function grants, RLS bypass, trusted historical rows, admin/superuser capabilities, replay and two concurrent first-device claims.
4. Official Play Protect classification review and safe Android build signing/distribution; no "Install anyway." Only after clearance, perform real Android-to-Supabase TEST proof, then bounded independently authorized enrollment, then two-phone E2EE tests.
5. Operational deployment plan with migration dry-run, rollback, auth session revocation checks and monitoring before touching live TEST; production remains HOLD.

**Phase 7I conclusion:** Staged-first-device/first-verified-signer hard-stop validated. **No actual first device authorized, no real independent security audit completed, no live deployment.**
