# V39 trusted-device enrollment — executable release gates (TEST ONLY)

Status: SECURITY HOLD. This is a test contract, not permission to deploy or change grants.

## Confirmed blocker
Authenticated users can call public.register_e2ee_v2_device(uuid,text,text) without a signed trusted-device approval. New V39 endpoints cannot secure enrollment while this route remains writable. messaging_devices also has an authenticated INSERT surface; inventory all writers.

## Implementation contract
- Establish initial verified authority independently; no automatic first-device enrollment, OTP-only trust, or self-attestation.
- Create an immutable candidate request with server-generated nonce, short expiry, account, candidate device ID, both public keys, trusted approver ID, and canonical transcript version.
- Verify approval signatures on the server against an independently verified, nonrevoked anchor with exact algorithm/key-type binding. Legacy Ed25519 must not be cast to P-256.
- Within one atomic transaction, lock request and anchor, verify signature, compare immutable candidate data, insert device, consume request, write unique approval receipt. Any failure rolls back.
- In same controlled cutover, deny legacy authenticated V2 RPC and direct table enrollment bypasses. Validate older client compatibility and recovery before changing grants.
- Never copy private keys, clear Android storage, or touch production.

## Go/no-go tests
1. Legacy authenticated RPC denied after cutover; no device created.
2. Unauthenticated and cross-account enrollment denied.
3. Unverified, self-proclaimed, or revoked approver denied.
4. Key swap, nonce mismatch, expired request, wrong device/account denied.
5. Replay and concurrent reuse produce at most one device and one receipt.
6. Receipt-write failure rolls back device insert and consumption.
7. First-device bootstrap and lost-device recovery require separate verified authority.
8. Phone 1 and Phone 2 demonstrate approval, secure messaging, restart persistence and recovery without data loss.

Do not deploy TEST until every gate passes on disposable Postgres and Android devices. Existing GitHub reference code and CI are not evidence of hosted TEST readiness.
