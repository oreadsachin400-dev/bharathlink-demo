# TEST device enrollment security gate — implementation contract

Scope: Supabase TEST project only. Never change DEMO, existing keys, or verification flags.

## Observed state (2026-10-30)
- bl20-pairing-gate v3 intentionally GET-only; pairingEnabled=false and registrationEnabled=false.
- public.request_messaging_device_enrollment accepts P-256 ECDH and P-256 signing JWKs, returning request UUID.
- public.get_my_messaging_device_enrollment_status is read-only.
- messaging_devices authenticated INSERT RLS with_check=false; approval RPC absent.
- 8 active messaging devices, 0 enrollment requests at audit time.

## Mandatory secure protocol before enablement
1. Authenticate both devices independently; bind enrollment to auth.uid(), random UUID, public key fingerprints, expiry, and one-time challenge.
2. On existing trusted device, require possession proof: sign domain-separated canonical payload including request ID, new device UUID, both key fingerprints, expiry, approver device UUID, and server nonce. Validate signature server-side against already-registered signing key. Never trust client-supplied approver key.
3. Enforce approver ownership, active/not revoked status, immutable key binding, single-use challenge, expiry, and replay-safe atomic transaction with row locks.
4. Server inserts approved new messaging device via tightly scoped SECURITY DEFINER RPC; never loosen INSERT RLS. Ensure approved public keys match request exactly.
5. Bootstrap first device requires independent high-assurance identity verification; do not automatically trust a logged-in new device.
6. Persist private keys securely on Android (Android Keystore-backed where feasible); never send private keys or raw key material to server. Distinguish P-256 enrollment from separate E2EE V2 Ed25519/X25519 registration.
7. Gate messaging behind server approval plus local account/device/key match; never mark a WebView shell as E2EE-ready based on login alone.

## Test acceptance
- Wrong user, revoked approver, altered key, expired request, replay, duplicate device UUID, malformed signature, and concurrent approvals all fail.
- Valid approval works exactly once, scoped to account, and preserves preexisting devices and keys.
- First-device bootstrap without verified independent proof fails closed.
- Two physical phones exchange and decrypt E2EE messages after successful approval.
- Existing DEMO and production remain unchanged.

Status: design contract only. No approval implementation, enrollment activation, or E2EE test pass claimed.
