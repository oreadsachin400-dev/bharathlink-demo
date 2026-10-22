# V38 actual web E2EE caller compatibility findings — 2026-10-22

Source inspected: `index.html` on `security/v38-postgres-isolated-ci`, approximately 917 kB. This is repository source, NOT proof of deployed TEST contents.

## Two distinct enrollment paths
**Messaging:** `E2EEBackend.activate()` reads IndexedDB `bharathlink-e2ee-v2`, generates a nonextractable ECDH P-256 key, exports its public JWK, then POSTs directly to `/rest/v1/messaging_devices` with `user_id`, `device_label`, `public_key_jwk`, `key_algorithm: ECDH-P256`. It subsequently stores the private CryptoKey and returned device ID in IndexedDB. An active saved local device is reused after `is_my_messaging_device_active`. The source does NOT require an existing trusted-device signature before a fresh messaging device insert.

**Separate V2 diagnostic:** `E2EEV2DeviceTest` uses IndexedDB `bharathlink-e2ee-v2-device-test`; generates nonextractable X25519 and Ed25519 signing keys (ECDSA P-256 fallback). It has a legacy `register_e2ee_v2_device` RPC interface, but the isolated branch's `run()` explicitly fails closed before calling it. This is NOT the same device registry or cryptographic protocol as the main messaging implementation.

## Consequences
- The V38 P-256 approval verifier does not automatically authorize Ed25519 diagnostic keys; signing algorithm and trusted anchor key format must be explicitly negotiated and validated.
- The V38 two-key candidate digest is NOT the same as the messaging P-256 public JWK registration. Do not equate either identity or claim unified enrollment.
- Disabling the diagnostic V2 RPC does not secure `messaging_devices` direct REST inserts. Its RLS policies, triggers and all writers require an independent server-side authorization path.
- New-device registration must not be turned off without a tested first-device bootstrap, existing-account migration and recovery path. Otherwise legitimate Android first installs may lock out.
- No production or deployed TEST change has been made.

## Next implementation gate
1. Decide and document whether messaging devices will remain P-256 ECDH or be migrated to V2 X25519, with explicit compatibility/dual-device migration.
2. Inventory all direct `messaging_devices` inserts and policy grants; enforce signed enrollment at the DB trust boundary rather than UI alone.
3. Bind the candidate's actual messaging encryption public key, signer public key, account ID, request ID, expiry and nonce in a canonical signed transcript.
4. Execute disposable-DB concurrent/replay/rollback and two-device tests before staging any TEST migration.
5. Re-check deployed TEST source and Android WebView storage isolation separately; repository branch code alone is not deployed proof.

Status: CRITICAL DESIGN GAP IDENTIFIED; NOT YET REMEDIATED.
