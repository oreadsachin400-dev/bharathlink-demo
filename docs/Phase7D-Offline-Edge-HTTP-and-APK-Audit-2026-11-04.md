# BharathLink Phase 7D — Offline real Edge handler HTTP contract + APK static review
**4 November 2026 | TEST-only. No Supabase writes, no deployment, no Android APK release.**

## Source control and final CI
- Branch: `bharathlink-phase7d-offline-http-proof-ci-test`
- CI workflow: `.github/workflows/phase7d-offline-edge-http-ci.yml`
- Verified Actions run: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41700825188
- Outcome: **2/2 jobs SUCCESS**.
- Node v22 executed **21/21 tests PASS**, 0 failures/skips in `candidate-possession.test.mjs`, `phase7b-challenge-crypto.test.mjs`, and `phase7d-edge-http-contract.test.mjs`.
- Real ephemeral PostgreSQL 17 CI regression PASS: owner scoping, expiry, invalid digest, one-time consumption, concurrent replay (exactly one succeeds), no device-trust writes.

## What the new HTTP test covers
- Loads actual `supabase/functions/bl20-candidate-possession/index.ts` source.
- First verifies **original** `const FEATURE_RELEASED=false;` returns 503 without reaching auth or RPC.
- To exercise the otherwise unreachable code, creates a **throwaway temporary copy only on the GitHub Actions runner** with the flag enabled. The committed source and deployed TEST Edge remain disabled.
- Injects synthetic, in-memory `Deno.serve`, `Deno.env`, and `fetch` handlers. All outgoing requests are restricted to `https://synthetic.invalid`. No live internet or database is consulted.
- Generates independent ephemeral P-256 ECDSA and ECDH keys; the synthetic server emits canonical short-lived challenge payload bound to authenticated user ID, proof ID, device ID, nonce and the hashes of both public keys. The mock Android signing output is DER encoded then verified by the **actual** Edge implementation's WebCrypto verifier.
- Tests valid start/finish, replay rejection, two concurrent finishes, other-account attempts, forged client userId, wrong key, altered signed payload, expired challenge, invalid public JWK, invalid bearer, origin restriction and HTTP method.
- Responses must report `serverApproved=false`, `trustedDevice=false`, `e2eeV2Ready=false`. These prove **candidate possession only**, not independent identity.

## Independent offline static check of previously generated Phase 7A APK
Audit target was the existing exact-file APK whose SHA-256 also appears in the Play Protect appeal:
`a16768f0ee8519ecd144ac032c54d32a3735aa6a09577d3f4fc080be77e6cd7e`.
- APK ZIP structure passed integrity check; contains `classes.dex` through `classes4.dex`, manifest and resources.
- Android binary manifest decoded directly:
  - Package `com.bharathlink.app.test.phase7bind`.
  - `versionCode=1`, `minSdk=31`, `targetSdk=34`.
  - Declared permission **only** `android.permission.INTERNET`.
  - `application android:debuggable=true` (debug CI test build).
  - `allowBackup=false`, `usesCleartextTraffic=false`.
  - Only one declared exported activity, `Phase7AuthBindActivity`, for `MAIN/LAUNCHER`. No additional service, receiver, or provider in manifest.
- Embedded app-specific DEX string inspection found the configured Supabase-20-TEST domain and local TEST signing aliases; this is **not** comprehensive malware analysis.
- The static review is not proof that this APK is safe. Play Protect classified it as **Harmful app blocked**. Google Play Protect's own scan/detection reason remains unknown and the appeal has been **submitted, not approved**. VirusTotal's positive no-detection report did not supersede Google Play Protect (the Google vendor timed out).
- **Never advise bypassing Play Protect, toggling it off, or installing anyway.** Debug signing may be one relevant distribution characteristic but is not an established cause of the warning.

## Non-changes and security holds
- No production/TEST Supabase Edge deployment, no private credential changes, no RLS changes, no database migrations, no remote device approval.
- A read-only query after CI still showed **8 preexisting messaging device rows, 0 candidate proof rows, 0 pending enrollment requests, 0 verified signing keys**.
- Original KeyPrep private keys, package and E2EE data were untouched.
- Phase 7C remains source-only; no new APK was released.
- **No real authenticated Android-to-Supabase challenge has been executed**. CI verifies a synthetic HTTP simulation and isolated SQL regression, not physical E2EE.

## Next gates
1. Resolve Play Protect classification through official processes and independently review debug signing/distribution before any new APK install.
2. After cleared, test exact TEST native signing flow against separately authorized, scoped challenge endpoint; keep trusted-device promotion OFF.
3. Establish independently verified first-device enrollment; only then test two physical Android devices with E2EE.
