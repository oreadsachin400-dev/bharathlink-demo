# V38 E2EE V2 enrollment migration contract — NOT FOR LIVE
Status: SECURITY HOLD. No migration or RPC replacement authorized.
Verified TEST schema (2026-10-22): public.e2ee_v2_devices(device_id,user_id,signing_public_key,curve25519_public_key,protocol_version,created_at,last_seen_at,revoked_at). public.messaging_devices is a DIFFERENT ECDH-P256 registry with public_key_jwk and its own direct INSERT policy.

## Mandatory atomic server transaction
1. Authenticated account identity comes only from validated JWT. New enrollment requests store canonical V2 signing and X25519 public keys, their domain-separated digest, nonce hash, approver device ID, expiration, and immutable request ID.
2. Approval signature is verified by trusted server code against the CURRENT non-revoked approver signing key. The signed transcript includes account, request, candidate, approver, digest, nonce hash, and expiry. A caller-supplied verified=true flag is never proof.
3. The finalizer uses one DB transaction to lock the pending request and approver anchor, revalidate all immutable fields, account ownership, expiry and current revocation, insert public.e2ee_v2_devices with both original keys, record a UNIQUE one-time receipt, and transition request to consumed. Roll back on any mismatch/conflict.
4. The finalizer must not be callable by authenticated/anon directly with a claimed verified result. Prefer a private backend service that authenticates, verifies and commits through a narrowly scoped trusted transaction path. Check TOCTOU and crash/retry behavior.
5. After compatible Android onboarding and existing-device inventory are verified, revoke legacy register_e2ee_v2_device execution for unapproved paths and remove all direct INSERT bypasses in a SINGLE tested migration. Preserve existing keys and identities. Do not drop/rotate keys.
6. Separately audit messaging_devices direct INSERT and UPDATE policies and all SECURITY DEFINER functions. Its P-256 public_key_jwk is NOT the V2 signing key and must never be substituted for an E2EE signing trust anchor.
7. First-device bootstrap and lost-device recovery require separate policy and authenticated recovery proofs; neither may silently bypass existing-device approval.
8. Negative tests: unsigned, invalid signature, different signing key, different Curve25519 key, wrong account, wrong candidate ID, self-approval, revoked approver, expired request, duplicate/replay, concurrent finalize, legacy RPC bypass, direct table INSERT, crash after insert before receipt, and rollback invariants.

## Release gate
Do not deploy until source review, isolated concurrency tests, read-only data inventory, rollback plan, Android first-install + linked-device tests on both physical phones, and a consolidated security signoff. Production must remain unchanged.
