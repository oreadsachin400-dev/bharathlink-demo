# V39 live enrollment cutover — SECURITY HOLD (24 Oct 2026)

This is a release-blocking review, NOT a deployment instruction. No production or TEST DB mutation is authorized.

## Source-verified facts
- `enroll_approved_v2_reference.mjs` validates signed P-256 approval against `verified_approvers` via the PostgreSQL adapter, but **the initial independently trusted approver has not been established**.
- `v39_legacy_device_proof_REFERENCE_NOT_DEPLOYED.mjs` checks Ed25519 possession of an existing key. Possession alone is NOT evidence that the key was independently verified, and does not authorize candidate enrollment.
- `public.register_e2ee_v2_device(uuid,text,text)` remains an authenticated enrollment bypass according to the last live TEST audit. Do NOT revoke this RPC until a tested replacement and recovery path exist.
- Android WebView and Chrome do not share private E2EE key storage. Do not copy keys or auto-enroll an unrecognized WebView.
- The P-256 JWK approver flow must not silently interpret 32-byte legacy Ed25519 keys as P-256.
- Green CI proves isolated reference/disposable database behavior, not live TEST readiness.

## Mandatory evidence before TEST deployment
1. Independently verified first-device authority and a separate lost-device recovery flow, with documented threat model, proof lifecycle, expiry and abuse limits.
2. Explicit Ed25519-vs-P-256 algorithm discovery for existing records, with physical-device nonce signature verification; no key-format guessing.
3. Server-generated immutable candidate request; account/device/keys/nonce/expiry bound in canonical signed transcript.
4. Trusted server authentication, row-locked verified nonrevoked approver, atomic insert/consume/unique receipt and rollback on all failures.
5. Inventory ALL authenticated writers to device registration (RPCs, tables, functions, triggers, service routes). In one controlled cutover, deny bypass writers and verify legacy clients/recovery still work.
6. Disposable PostgreSQL tests for denied old RPC, replay, concurrency, cross-account, key swap, revoked/unverified approvers, rollback and receipt uniqueness.
7. On two physical Android TEST phones: login, secure approval, E2EE messaging, restart persistence, background calling and recovery without private-key loss.

## Go/no-go
NO-GO until all seven evidence groups have independently reviewed PASS artifacts. Keep existing E2EE data, RPC privileges, TEST and production deployments unchanged in the meantime.
