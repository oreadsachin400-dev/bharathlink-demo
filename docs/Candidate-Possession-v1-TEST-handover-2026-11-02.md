# BharathLink — Candidate Device Proof-of-Possession v1 | 2 November 2026

**Status: TEST backend staged, hard-disabled; Android challenge signer source staged. NOT approved for real enrollment.**

## Scope
- Supabase: **BharathLink-20-TEST** only (`fsdusofbpwdrdvgexxyw`).
- GitHub feature branch: `bharathlink-candidate-proof-v1-test` (from `bharathlink-device-keyprep-v1-test`).
- Prior physical Android validation: KeyPrep-only launcher, P-256 signing and ECDH public JWKs, local self-check, and key persistence **PASS**. Preserve that installed package and private keys.
- No changes to production, DEMO, existing users, existing device-key rows or verification flags.

## Implemented
1. Private, RLS-enabled candidate proof table `bl20_candidate_v1_private.proofs`: 5-minute expiry, unique random challenge, one-time consumption, account/device association and request rate controls.
2. Service-role-only TEST RPCs:
   - `bl20_candidate_proof_start`
   - `bl20_candidate_proof_context`
   - `bl20_candidate_proof_finish`
   - `bl20_candidate_proof_payload` (private helper, not granted to public callers).
   Ordinary `anon` and `authenticated` roles cannot directly invoke these functions.
3. Server-selected, domain-separated challenge payload:
   `BHARATHLINK_CANDIDATE_POSSESSION_V1` + authenticated owner UUID + proof UUID + device UUID + challenge UUID + UTC expiry + SHA256 of ECDH public-key fields + SHA256 of signing public-key fields.
   A subsequent v1.1 migration standardizes fingerprint input to UTF8 `EC\nP-256\n<x>\n<y>`, byte-identical across Android, JS and Postgres.
4. Edge Function `bl20-candidate-possession` **v1**: valid JWT required, validates user via Supabase Auth, imports public P-256 keys, confirms ECDSA-DER signature against server-selected payload, binds payload hash in a DB transaction and returns possession result only.
   **Hard disable:** `FEATURE_RELEASED=false` in deployed source. This is an intentional no-enrollment safety gate.
5. Android native `LocalApprovalKeys.signCandidateServerChallenge` source (not exposed in the current phone UI): checks canonical domain, local account UUID label, device ID, 5-minute expiry, local ECDH/signing public-key fingerprints and signs using non-exported AndroidKeyStore private P-256 key. No network call, no JS bridge, no trust activation.
6. Automated tests: real ECDSA P-256 signatures and negative paths; disposable PostgreSQL test of ownership, exact fingerprint, invalid key shape, duplicate challenge, expired challenge, replay, and no trust escalation.

## Evidence
- GitHub cryptographic + disposable PostgreSQL workflow:
  https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41419760272 — PASS after fingerprint test correction.
- Latest native signer compilation workflow:
  https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41419811511 — **SUCCESS** (Kotlin unit tests + compile).
- TEST database permission check: public/authenticated execution denied; service role only.
- TEST current state after migration: **8 active messaging devices, 0 enrollment requests, 0 candidate proofs, 0 independently verified signers**.
- Existing `messaging_devices_insert_trusted_approval_only` RLS `WITH CHECK false` unchanged.
- Existing `bl20-device-approval` still hard-disabled; no new device is trusted.
- Supabase security advisor: private candidate table has informational `rls_enabled_no_policy` finding, intentional because it is private and not directly accessible; do not add client RLS policies to expose it.

## Explicitly NOT complete
- Authenticated native mobile session binding to the correct user (the UUID typed into the offline utility is only a label).
- A live signed proof from that actual phone to the TEST backend (endpoint currently disabled).
- Independently verified first-device bootstrap / audited recovery; there are **zero** eligible trusted approver keys.
- Server-approved device enrollment, actual Android E2EE-v2 Ed25519/X25519 key provisioning, and encrypted two-phone send/decrypt.
- Calling, messaging, mail or payments must NOT be enabled based on local key possession.

## Next engineering gates (no shortcuts)
1. Implement mobile OAuth/PKCE or equivalent verified native authenticated session and explicitly bind Supabase `auth.getUser()` identity to the local device UUID and public keys. Never accept user-typed account UUID as authority.
2. Security review and release-control change for the candidate possession endpoint, with rate limits, robust audit logging, and actual mobile signatures against server-issued one-time challenges; keep trust/approval off.
3. Establish an independently audited first-device verifier or pre-existing genuinely verified approver (cannot fabricate a trust anchor).
4. Complete separate approval protocol, native key/device receipt verification, Ed25519/X25519 E2EE setup, and two-physical-phone ciphertext exchange tests.

**No new APK needs to be installed for this staged backend phase.**
