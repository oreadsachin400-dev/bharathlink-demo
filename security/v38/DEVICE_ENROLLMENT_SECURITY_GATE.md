# Device enrollment security gate — audit finding (2026-10-22)

Status: **HOLD — design and review only; no live migration**.

## Verified from 20-user TEST read-only catalog

- `public.register_e2ee_v2_device(device_id, signing_public_key, curve25519_public_key)` checks authenticated identity, canonical key encoding, existing device ownership, revocation and key conflicts.
- Its currently deployed body does **not** require an approved pairing request, a consumed one-time authorization, or a verified signature from an already trusted device before first insert.
- `bl_pairing_private.requests` stores candidate JWK, challenge nonce, status, expiry, approving device and approval timestamp; these fields alone are not proof that a cryptographic authorization is bound to the E2EE device keys.
- `bl_pairing_private.trust_anchors` is a separate trust registry. Merely checking its existence is insufficient to authenticate a new device.

## Required fail-closed implementation (not yet deployed)

1. Establish the current first-device/bootstrap and account-recovery model explicitly; do not strand existing two-phone TEST users.
2. Define a versioned, domain-separated approval transcript binding user ID, candidate device ID, exact signing and X25519 public keys (or canonical hashes), trusted approver ID, challenge nonce, issued/expiry times, and purpose.
3. Verify approver signature with the pinned trusted public key and check revocation, ownership, challenge expiry, and challenge consumption.
4. Atomically consume the approval in the **same transaction** as device enrollment, protected by unique constraints and row locking. No standalone `approved=true` flag.
5. Keep the old registration RPC unavailable for new devices only **after** Android/Chrome clients have migrated to the approved flow; do not remove existing keys or overwrite devices.
6. Run negative tests: replay, wrong user, mismatched key, wrong device, revoked approver, expired challenge, concurrent double submit, failed transaction rollback, recovery/bootstrap.
7. Validate on an isolated PostgreSQL instance and two physical Android TEST devices; only then consider staged TEST migration. Production stays untouched.

## Security boundary

Never commit private signing keys, service-role tokens, database URLs, or real user device records. V38 CI green is evidence about its isolated test suite, **not** evidence of deployed enrollment security.

This is a review artifact, not an authorization to run DDL or deploy.
