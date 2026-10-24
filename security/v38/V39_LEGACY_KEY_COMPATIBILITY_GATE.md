# V39 legacy signing-key compatibility — SECURITY HOLD
Observed on hosted 20-user TEST on 2026-10-24 (read-only):
- One active row in public.e2ee_v2_devices.
- signing_public_key length = 44 characters; curve25519_public_key length = 44 characters.
- No private V39 verified approver anchors, pending requests, or receipts.
- Reference verify_approval.mjs verifies EC P-256 JWK signatures using SHA-256 and IEEE-P1363.
A 44-character encoded signing key is NOT a P-256 JWK. It may encode 32 bytes (e.g., Ed25519) but the algorithm is NOT proven by length alone.

REQUIRED BEFORE TRUST ANCHOR MIGRATION:
1. Inspect actual Android/web E2EE signing-key generation and serialization code, and establish exact algorithm, encoding and canonical signature transcript.
2. Prove possession of the corresponding private key on the existing trusted physical device with a fresh, one-time server challenge bound to account, device, key and expiration. Do not export the private key.
3. Implement algorithm-specific verification using verified public key bytes; do not convert legacy key bytes into a P-256 JWK or trust a client-supplied 'verified' flag.
4. Establish independent first-device bootstrap and lost-device recovery authority; no automatic fallback to OTP or logged-in JWT.
5. Add positive, negative, replay, cross-account and revoked-device tests; integrate atomic DB transaction and safely close legacy register_e2ee_v2_device only after replacement is live.
Until then: do not populate verified_approvers, disable existing user flows, deploy enrollment service, or claim Android E2EE readiness.

## Source audit addendum (2026-10-24)
Inspected `index.html` on security/v38-postgres-isolated-ci. The `E2EEV2DeviceTest.generateLocal` function creates an X25519 key pair and tries a nonextractable WebCrypto Ed25519 signing pair, falling back to ECDSA P-256. It exports public keys as base64(raw bytes) and stores the selected signing algorithm in the local record. Its own source warns these are temporary V2 backend-plumbing test keys, not production identity/prekey keys. A 44-character Base64 public key is consistent with 32 raw bytes, but is not proof of the algorithm or possession. P-256 raw uncompressed public keys are not the same as a P-256 JWK and must not be silently coerced.

Before enabling any enrollment, match the *specific* database device to its local algorithm record and prove private-key possession with a fresh server nonce and verified signature. The P-256-only V39 reference verifier is not a safe drop-in for Ed25519 legacy signing keys. No live approver enrollment or legacy RPC revoke was performed.
