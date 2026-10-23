# E2EE trusted-device enrollment — security design gate

Status: DESIGN ONLY. Not deployed; no new device may be activated yet.

## Existing reality
- Messaging uses non-extractable ECDH P-256 private keys stored in IndexedDB.
- ECDH is a key-agreement primitive, not a device-approval signature.
- The TEST DB currently has an owner-scoped enrollment request RPC, a locked queue,
  and no direct authenticated INSERT permission on messaging_devices.
- The V2 device registration test RPC is a different protocol and must not be
  reused as authorization for messaging_devices.

## Required safe protocol
1. The new device creates a non-extractable ECDH key and a separate
   non-extractable signing key (prefer Ed25519 if supported, otherwise
   appropriately verified P-256 ECDSA). Keep private keys local.
2. New device submits a request bound to authenticated user ID, proposed device
   UUID, canonical public keys, protocol version and expiry. Server generates a
   random one-use challenge and returns a request ID. No device activation.
3. Trusted existing device independently authenticates and confirms its own
   active, non-revoked device identity. Server must know a separately registered,
   verified signing public key for that device. Legacy ECDH keys alone do NOT
   meet this condition; legacy migration needs independent identity proof.
4. User confirms matching short authentication string or QR out of band.
   Trusted device signs a canonical payload with domain separator
   'bharathlink.messaging.enrollment.v1', user ID, request ID, proposed device
   ID, both public keys (or collision-resistant hashes), challenge, issued_at,
   expires_at, and protocol version.
5. Server verifies signature against the active approver signing key,
   authenticates approver's session and account, checks approval eligibility,
   expiry, replay and request status, and atomically inserts messaging_devices
   plus consumes the request in one transaction.
6. Only after server confirmation should new device mark enrollment active.
   Never transfer old private keys, skip authorization, or fall back to plaintext.

## Mandatory negative tests
- Caller cannot approve own request using newly generated key.
- Cross-account approvals rejected.
- Revoked approver rejected.
- ECDH-only legacy device cannot masquerade as signer.
- Signature over another request, device, key, or account rejected.
- Expired challenge rejected; replay and concurrent double-consumption rejected.
- Network failure preserves keys and does not show 'approved'.
- No direct table insert or anonymous RPC access.
- Existing active devices and ciphertext remain unchanged.

## Release gate
Do not enable approval/activation RPC or mobile enrollment UI until the
server-verifiable trusted-device signing identity or a separately audited
first-device/recovery identity-proof process is established. No APK/Netlify
deployment is implied by this document.
