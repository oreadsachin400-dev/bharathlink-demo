# BharathLink Phase 7F — Proof-Gated Additional-Device Approval v2

**4 November 2026 | STAGED SOURCE + OFFLINE CI ONLY | NOT DEPLOYED**

## Verified checkpoint
- Branch: `bharathlink-phase7f-possession-gated-device-approval-ci`
- GitHub Actions workflow: `.github/workflows/phase7f-proof-gated-approval-ci.yml`
- [Final verified GitHub CI run #41704051070](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41704051070): **SUCCESS, 2/2 jobs**. **15/15 Node HTTP and static release-gate tests PASS, 0 failed/skipped**.
- Disposable PostgreSQL 17 tests PASS: missing proof, unproven proof, wrong owner, invalid approver digest, changed signing/ECDH keys, stale candidate proof, protocol v1 downgrade, replay, first-device denial; synthetic successful second-device proof-bound approval; parallel second-device approval exactly once, atomic candidate proof/device link.
- The new `supabase/functions/bl20-device-approval-v2/index.ts` starts with a literal `V2_RELEASED=false` and was **not deployed**. In CI only, a temporary local copy is enabled against synthetic HTTP mocks. The actual ECDSA-P256 verification implementation is exercised before invoking the mock v2 RPC.
- The SQL tests use synthetic keys and direct database state transitions for candidate possession. The end-to-end crypto possession check was separately tested in Phase 7E. Do not mischaracterize this as a real-world identity proof or live approval.

## Concrete security gap addressed
The prior `public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)` v1 trusted-device commit verified the existing approver's signature (in a protected Edge function), but **did not check a signed proof of possession of the new device's proposed ECDH and signing keys** before inserting the device.

Staged `sql/staged/TEST-device-approval-v2-candidate-possession-gate.sql` closes that gap with a new service-role-only **v2** RPC requiring:
1. Exact owner/request and a pending, unconsumed enrollment with protocol version **2**; reject downgrade.
2. A unique recent already-consumed candidate proof of possession with matching owner, proposed device UUID, ECDH public JWK and signing public JWK, within the 15-minute freshness window. Reject unproven, missing, expired/stale, mismatched and reused proofs.
3. The existing trusted approver's verified, nonrevoked signing key and unchanged approval context/digest validated by v1 inside one transaction. **The protected Edge must cryptographically verify the approver's P-256 signature before calling v2**.
4. A private RLS-enabled `bl20_candidate_v1_private.trusted_approval_links` table with unique proof ID, request ID and device ID to prevent repeated use and preserve an atomic audit link.
5. `FOR UPDATE` locking on the request/proof and v1's existing approver locks. Two simultaneous consumers cannot approve the same request twice.
6. In this staged migration **service_role EXECUTE on legacy v1 is revoked**; v2 is the only service_role commit route. Direct authenticated/anon EXECUTE remains denied.

## New source and tests
- `sql/staged/TEST-device-approval-v2-candidate-possession-gate.sql` — new staging-only transaction and unique link table.
- `supabase/functions/bl20-device-approval-v2/index.ts` — separate, hard-disabled v2 Edge adapter with user validation, approver P-256 signature verification and proof-bound RPC.
- `tests/phase7f-release-gates.test.mjs` — verify privilege boundaries, anti-downgrade, no first-device bootstrap, no Edge enablement.
- `tests/phase7f-approval-v2-edge-http.test.mjs` — temporary synthetic HTTP test; real cryptographic approver signature verified, wrong-account, missing proof, invalid signature and invalid JWT denied.
- `tests/fixtures/phase7f-possession-gate-assertions.sql` — actual disposable Postgres negative/positive cases.
- `tests/phase7f-parallel-approval.mjs` — two separate SQL connections compete to commit same proof; exactly one succeeds and replay fails.
- `.github/workflows/phase7f-proof-gated-approval-ci.yml` — both offline jobs, no deployment/credentials/APK.

## Live TEST state: read-only confirmed *after* CI
Project `fsdusofbpwdrdvgexxyw`:
- 8 existing `public.messaging_devices` rows (historical, **not automatically trusted**).
- 0 `public.messaging_device_signing_keys` rows with `verified_at IS NOT NULL`.
- 0 pending device enrollment requests.
- 0 candidate proof rows.
- Live service_role **still has access to original legacy v1 RPC**, because this Phase 7F v2 SQL has **not been deployed**. There is no live v2 RPC at this checkpoint. The deployed v1 Edge remains hard disabled; do not suggest v1 service grant was revoked live.
- No existing RLS, production, or DEMO changes. Original Android KeyPrep package, private keys and signing continuity unchanged.

## Important limits / HOLD
- **This does not implement independent first-device authorization.** Zero independently verified real signer/issuer anchors. Even a successful prior review *receipt* is not device approval.
- The new v2 Edge is not deployed; existing deployed approval Edge still calls v1 but remains hard disabled. The staged migration deliberately revokes v1 service execution so accidental activation would fail closed.
- No genuine user JWT or live Android-to-Supabase challenge exercised. No public Android APK produced and no Google Play Protect clearance. Prior harmful-app warning appeal has been **submitted but no reversal confirmed**. Do not bypass Play Protect.
- Before any real launch: audit auth session revocation (JWT `session_id` vs `auth.sessions`), rate limits, operations audit, key rotation, malicious approver/social engineering, issuer/reviewer governance and privacy/consent, recovery and first-device flow, independent pen test and secure release signing.
- Never enable by changing UI flags, Edge literals or granting direct authenticated database INSERT. Live E2EE V2 must remain unavailable until independent authorization and physical two-device verification.

## Next independent milestone
Design **Phase 7G first-device authorization governance** (trusted issuer, two-person independent reviewer controls, consent, key pinning, atomic identity and signer binding, revocation and audit trail) as a separate **staged-only** contract. This cannot honestly be marked approved without a real accountable authority and security/operational review. Keep Phase 7A physical Play Protect clearance as a parallel external blocker.
