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
