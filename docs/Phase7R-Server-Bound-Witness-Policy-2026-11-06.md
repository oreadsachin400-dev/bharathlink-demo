# BharathLink Phase 7R — Server-bound external witness configuration

**6 November 2026 | Staged, synthetic GitHub CI only | No deployment**

## Problem found in Phase 7Q
The local durable-checkpoint CAS function accepted `independentStorePath`, `witnessRegistry`, and `nowMs` as ordinary call arguments. The function explicitly warned these must come from a trustworthy, separate server process, but that critical trust boundary was **not enforced by its interface**. An unsafe integration could inadvertently let a client select a different SQLite file, provide its own signing key/registry, or set the time and thereby generate a convincing-looking synthetic checkpoint.

The new `recovery-gate/server-bound-witness-writer.mjs` is an **offline reference wrapper** that binds those sensitive values when a server-controlled writer is constructed and **does not accept them per request**. This is a step toward safer integration, not a real independent-witness provider or proof of a legitimate issuer.

## Implementation
- `createServerBoundWitnessWriter` requires a strict configuration: absolute, pre-existing SQLite path, fixed log and witness key IDs, separate witness/issuer operator IDs, P-256 public JWK, independently distributed SHA-256 key fingerprint, validity window and server-owned clock callback.
- At construction, a domain-separated key-pin fingerprint is compared in constant time. The key coordinates and other trust settings are copied into a frozen internal snapshot, preventing later mutation of the original configuration object from silently rotating the signer or database location.
- The request surface accepts exactly `candidateCheckpoint`, `events`, and `checkpointSignatureBase64Url`. Extra fields (e.g. `witnessRegistry`, `independentStorePath`, `nowMs`) are rejected. The checkpoint must reference the configured project, log and witness key.
- An immutable copy of the caller's event objects and checkpoint is made **before any awaited cryptographic checks**, avoiding a common asynchronous caller-mutation vulnerability.
- The writer creates the Phase 7P witness verifier registry exclusively from the pinned configuration and passes it to Phase 7Q's transactional SQLite CAS writer. The original offline CAS tests remain intact.
- Every successful or rejected result retains `canActivate:false`, `deviceApproved:false`, `e2eeReady:false` and `enrollmentCommitted:false`.

## Tests and evidence
`tests/phase7r-server-bound-witness.test.mjs` checks accepted synthetic signed extension, replay, caller-supplied registry/path/clock spoofing, mutation of the construction policy after writer binding, forged signatures, wrong log/project, signature-key pin mismatch, expired policy, absent store and asynchronous modification of event input. GitHub CI also retains Phase 7I–Q regressions.

No user credentials, real external signing keys, Supabase RPC or data, Android APK or production infrastructure are involved.

## Explicit security limitations
- An attacker who can **construct the policy** or edit the trusted server's configuration, file system, code or signing key can still forge the trust boundary. An independently governed external witness must provision and distribute the verification-key fingerprint *out of band*, control the storage path and operating identity, and ensure server API requests never call this factory.
- This writer is **not a network service**, not an HSM and not a real independent witness. It uses experimental Node 22 `node:sqlite`; a filesystem administrator can modify SQLite databases, schema and triggers. Real operation requires hardened external audit storage, CAS with out-of-band verifiable checkpoints, identity and approval governance, key rotation and revocation, and independently retained/monitored logs.
- The lower-level Phase 7Q `persistCheckedWitnessCheckpoint` function still exists for offline tests; a future production API must **not expose that raw function**. An independently audited service integration and privilege review are required before shipping.
- The signature means a pinned key signed an observation, not that the observation is true, that a reviewer had legal authority, or that a device is trusted. No authentic issuer/reviewer/witness organisation has yet been provisioned.
- No stored E2EE private keys are reconstructed here. Old chat histories still require the original compatible keys or a separately reviewed encrypted backup.

**Release verdict: KEEP DRAFT / SECURITY HOLD. Do not deploy Supabase/Netlify/APK, merge staged branches, reset keys, or uninstall an existing key-bearing Android app.** The physical Sachin/Nidhi two-phone decryption tests can only follow genuine independent first-device trust, signing-key continuity and operational security review.
