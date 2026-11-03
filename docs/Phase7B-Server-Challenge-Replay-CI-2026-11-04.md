# BharathLink Phase 7B — Candidate Possession Challenge & Atomic Replay CI
**4 November 2026 | Source and isolated GitHub CI only — no release or deployment**

## Context
- Phase 6 physical Android offline P-256 local signing, tamper rejection, ECDH, and key-presence-after-restart: PASS.
- Phase 7A local account-key-matching TEST APK: CI compiled/PASS but Play Protect displayed "Harmful app blocked" during physical install. A Google appeal was submitted. VirusTotal reported no vendors flagged this exact file, but this is not a guarantee of safety and the Play Protect warning has **not** been cleared. Do not bypass it.
- Original KeyPrep installed keys and signing certificate remain unrecovered/untouched. Never replace or uninstall it.

## Why no duplicate remote enrollment backend
A prior `bl20-candidate-possession` Edge function and the `bl20_candidate_v1_private.proofs` PostgreSQL table already exist on BharathLink-20-TEST. The deployed Edge handler is deliberately hard-disabled via `const FEATURE_RELEASED=false`, and is **not** reenabled by this branch. The existing `bl20_candidate_proof_start/context/finish` SQL API constructs a database-origin canonical payload, is account scoped, expires in 5 minutes, uses private RLS and service-role-only RPC grants, and consumes a proof under `FOR UPDATE` row lock. A correctly validated possession proof never sets trusted-device or E2EE-ready state.

## What this branch actually validates
- Runs WebCrypto P-256 signature verification using Android-style DER ECDSA signatures; tests altered account, proof ID, device ID, nonce, expiry, or public key hashes, wrong signing key, malformed JWK and signature.
- Starts ephemeral PostgreSQL 17 inside GitHub Actions. Applies the existing *staged* candidate SQL to this **throwaway CI database only**, with synthetic auth users, no phone data or production keys.
- Database smoke assertions exercise real start/context/finish, reject mismatched account, forged digest, duplicate pending request, expired challenge and replay. Assert `serverApproved=false`, `trustedDevice=false`, `e2eeV2Ready=false`.
- Issues simultaneous finish requests from two separate PostgreSQL connections. Exactly one is permitted by the row lock; second request and later replay fail.
- Checks anonymous and authenticated roles do not get direct RPC grants.
- Confirms no new `messaging_devices` rows are produced.

## Hard limits
These synthetic CI checks do **not** demonstrate that an unblocked Android phone signed a genuine Supabase-issued challenge, that a live user session was bound to a device key, that live Supabase RPCs have been exercised, or that a real identity authority approved a first device. The private PostgreSQL test database is **not** the live Supabase TEST database. There is no new APK in Phase 7B. The Phase 7A physical installation remains blocked; no Play Protect bypass is appropriate.

## Release gate HOLD
Do not flip `FEATURE_RELEASED`, grant broad database access, write directly into `messaging_devices`, mark trusted or E2EE-ready, or deploy this branch to production.

## Next independent work
Investigate the Phase 7A Play Protect classification and stable signing/distribution; after cleared, integrate a native Android signer of the exact *server-issued* canonical payload using the account-matched current-package AndroidKeyStore private key, send DER base64url signature through authenticated test Edge path, and run a bounded end-to-end TEST with explicit approval. Independently approved first-device identity and two-device encrypted messaging are distinct later gates.

## Branch and workflow
- Branch: `bharathlink-phase7b-challenge-possession-ci-test`
- Workflow: `.github/workflows/phase7b-candidate-proof-ci.yml`

**CI success must be verified from actual run, not inferred from a commit.**


## Native source-only signer (additional Phase 7B work)
- `android-phase7b/Phase7bChallengePolicy.kt` validates exact server challenge domain, verified account UUID, local device ID, proof ID, nonce, UTC expiry within five minutes, and the signed two public key hashes. No locally generated user-entered challenge is accepted.
- `android-phase7b/Phase7bCandidateSigner.kt` prepares **public** JWKs from this new TEST package's AndroidKeyStore; after the caller has a valid, foreground-verified TEST Auth session and stored fingerprint match, it signs the exact server-supplied payload with an existing non-exportable P-256 signing alias as DER/base64url. It cannot read the old KeyPrep or Phase 6 aliases.
- `android-phase7b/Phase7bChallengePolicyTest.kt` adds positive and negative tests for mismatched account/device/proof, expired/future payload, tampering, and malformed fields.
- `.github/scripts/v36hf_phase7b_compileonly.py` stages these sources over isolated Phase 7A scaffolding. The Phase 7B workflow compiles them and runs JUnit tests but does not upload or issue a new APK.
- There is **no** native end-to-end network invocation yet, no physical install and no change to the existing TEST Edge gate. Never claim server device enrollment or Play Protect clearance from this compile-only result.
