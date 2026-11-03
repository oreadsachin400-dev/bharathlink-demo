# BharathLink Phase 7G — First-Device Governance Intent & Consent Withdrawal

**Checkpoint: 4 November 2026 | Source and disposable PostgreSQL CI only | NOT DEPLOYED**

## Verified results
- GitHub branch: `bharathlink-phase7g-first-device-governance-ci`
- GitHub workflow: `.github/workflows/phase7g-governance-review-only-ci.yml`
- Verified [GitHub Actions run #41707639236](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41707639236): **SUCCESS**; **2/2 jobs PASS**.
- Source contract: **6/6 Node tests PASS, 0 failures/skips**.
- PostgreSQL 17 disposable CI passed the **genuinely P-256-signed synthetic review** from Phase 5, one-time review receipt consume/replay rejection, governance denial cases, parallel governance intent exactly once, audited consent-withdrawal veto, and no first-device insertion.
- The test issuer, reviewers, sessions and person are **synthetic**. This is **NOT** real-world identification or an independent identity-verification authority.

## New source
- `sql/staged/TEST-first-device-governance-intent-v1.sql` — new **private** `bl20_first_device_v1_private` schema with RLS-enabled `review_intents` and append-only `audit_events` tables. The intent's possible statuses are **only** `governance_pending_review_only` and `governance_vetoed`; there is no authorized/approved/trusted status.
- `bl20_first_device_v1_private.stage_review_intent(user,session,challenge)` — **SECURITY INVOKER**, owner-only; no `anon`, `authenticated`, `service_role` EXECUTE or schema USAGE. Consumes no new identity approval; stores a one-time review-only intent only after protected signed-review receipt has already been consumed. It rechecks account and active Auth session, consent time, two distinct non-account reviewers, issuer status, candidate P-256 possession, matching ECDH/signing JWKs, enrollment request protocol **3**, receipt payload and attestation hashes, and denies if an existing verified trusted signer exists.
- `bl20_first_device_v1_private.veto_review_intent(intent,reason)` — privileged owner-only; permitted reasons `consent_withdrawn`, `issuer_revoked`, `review_disputed`, `security_hold`. Records a single irreversible veto plus audit event; repeat veto denied.
- `tests/fixtures/phase7g-governance-denials.sql` — real DB negative checks for owner/session mismatch, expired session, issuer/case revocation, invalid consent, tampered receipt digest, altered key, protocol downgrade and already verified signer.
- `tests/phase7g-concurrent-intent.mjs` — two real independent `psql` processes race to stage one intent; exactly one succeeds, replay fails and audit count is one.
- `tests/fixtures/phase7g-veto-audit.sql` — only permitted reason accepted, consent withdrawal veto recorded once, both audit events retained and no device changed.
- `tests/phase7g-governance-contract.test.mjs` — source release gates, no public RPC or device-write code, no real issuer provisioning, hard-disabled existing Edge functions.
- `.github/workflows/phase7g-governance-review-only-ci.yml` — isolated CI. No APK, Supabase deployment, migration to live TEST or secrets.

## Security properties and limits
1. **Real first-device authorization is still BLOCKED.** The migration produces ONLY a case review intent and explicitly returns `independentAuthorityVerified=false`, `deviceApproved=false`, `trustedDevice=false`, `e2eeV2Ready=false`.
2. Existing independent receipt is signed by the synthetic issuer key in CI. The function compares the stored review payload hash and signature hash to current DB evidence; it **does not itself re-verify cryptography** or establish that an operating review authority exists. The signing verifier is exercised earlier in Phase 5 and no first-device activation is ever inferred.
3. Phase 5 receipt currently does not persist an immutable **issuer key fingerprint** captured at review consumption. Phase 7G snapshots the currently registered issuer key fingerprint in a review-only intent; it cannot prove key continuity from the moment the receipt was signed. An audited immutable issuer-pin receipt and revocation/rotation policy are prerequisites for a future actual authorization service.
4. Two reviewer UUIDs are constrained to differ and not match the account owner. This **does not establish real human independence**, qualifications, anti-collusion or organization affiliation; those need accountable third-party governance and audit.
5. Stored consent timestamp and veto are **mechanisms**, not independent proof of legally valid informed consent; final release needs appropriate user UX, disclosure, withdrawal and data-retention controls.
6. Session verification checks active `auth.sessions` and expiry but a final high-assurance system must independently assess auth-session revocation/rotation, account recovery fraud, signer keys and key lifecycle at the transaction boundary.
7. This Phase 7G schema is NOT an API; no Edge deployment, no service role grant, and no trust-commit transaction exist. A database superuser/migration owner can operate private tables: governance/dual-control of such access is an external prerequisite.
8. `public.messaging_devices` and `public.messaging_device_signing_keys` are never inserted/updated by Phase 7G. Never infer trust from historical devices.

## Live TEST verification (read-only, after CI)
Supabase project: `fsdusofbpwdrdvgexxyw`.
- 8 historical messaging devices; **0 independently verified signing keys**.
- 0 pending enrollment requests; 0 candidate proof rows.
- Private Phase 7G schema **absent** from live TEST.
- Staged Phase 7F v2 approval RPC **absent** from live TEST; old v1 RPC remains present (Edge hard-disabled).
- All original KeyPrep and Android signing/key data untouched. Phase 7A Google Play Protect harmful-app warning not confirmed resolved; previous appeal was submitted, not approved. **Do not bypass or install anyway.**

## Unresolved real-world release gates
- Independently contracted and audited identity-proofing authority with pinning, key rotations/revocation, organization controls, audit logs and two distinct authorized reviewers; no synthetic issuer in production.
- User consent and withdrawal UX plus retention/deletion, fraud recovery and dispute rights.
- Signed immutable issuer-key receipt upgrade and online cryptographic verification integrated with DB state and session.
- A separately reviewed high-assurance **first-device approval transaction** (not Phase 7G governance intent) with atomic enrollment, signer verification, account binding and strict downgrade refusal.
- Play Protect classification/resolution, safe Android distribution and original KeyPrep signing continuity. No forced install or private-key export.
- Formal pen test, production threat model and two physical-device E2EE V2 tests after independent authorization.

**Next safe coding step:** design a separate issuer-key immutability/revocation audit contract (review-only) before attempting actual first-device trust. Deployment or public activation is not justified by these synthetic tests.
