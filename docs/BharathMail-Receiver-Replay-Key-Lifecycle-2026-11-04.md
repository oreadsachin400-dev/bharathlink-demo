# BharathMail — Receiver Receipt Replay, Durable Pinning and Key Revocation (OFFLINE / HARD HOLD)

**4 November 2026** | Branch: `bharathlink-mail-smtp-replay-key-lifecycle-postgres-ci`

## Verified result

- [GitHub Actions #41828267644](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41828267644): **2/2 jobs successful**, **201/201 Node tests PASS** with **0 failures or skips**:
  - 58/58 existing + new offline SMTP cryptographic, replay-policy and full RFC/authentication tests
  - 142/142 pre-existing Mail Trust / device authorization / security regression tests
  - 1/1 real loopback-SMTP-to-ephemeral-P-256-to-disposable-PostgreSQL integration test
- The PostgreSQL 17 job independently passed staged SQL policy assertions and **24 parallel psql consumers**, enforcing exactly one initial receipt plus 11 idempotent duplicates, then one new receipt plus 11 cross-message nonce replay rejections.
- Both earlier and new TEST records, role checks, revocations, expiry checks and key pins use **synthetic or ephemeral** data, never live user email, production DNS or a production private key.

## Implementation

### 1. Receiver-key pins and revocation (TEST SQL)

`sql/staged/TEST-bharatmail-receiver-key-replay-v1.sql` (not a production migration) creates:

- `bl_mail_receiver_pins_test_v1`: append-only, syntactically validated public P-256 JWK, immutable key ID and validity interval. Key rotation adds a new key row; an existing key's public material or dates cannot be overwritten.
- `bl_mail_receiver_revocations_test_v1`: append-only irreversible revocation row per key ID. DB does not allow reactivation.
- `bl_mail_receiver_consumed_test_v1`: unique nonce and provider ID, full original MIME SHA-256 and signed receipt digest, timestamp and pinned key. Append-only audit receipt; no raw mail body or private keys.

The consumer and revoker functions share an advisory transaction lock keyed to the receiver kid to serialize revocation vs receipt consumption; PostgreSQL unique constraints enforce cross-process replay resistance. Exact repeat reports are idempotent only while the key remains valid. Reusing a nonce for another provider, a provider with another nonce, or changing any bound digest is denied. Expired, future and revoked keys are denied. All receiver tables and functions are denied to `anon`, `authenticated` and `service_role`; the disposable test DB operator is intentionally the only writer. There is no user-facing SQL grant.

**Important boundary:** SQL itself does NOT validate ECDSA signatures and MUST NOT be treated as a standalone sender authenticator. The cryptographic verifier must run before a tightly scoped, independently audited storage operation. No deployment is authorized.

### 2. Cryptographic verification before the ledger

`mail-verifier/verify-and-consume-receiver-test.mjs` validates the signed SMTP receipt using `verifySmtpReceiverReceipt` and a public key loaded independently from the intended pinned registry. It verifies raw MIME SHA-256, provider ID, expected sender/recipient, key ID, receipt time and P-256 signature **before** asking the isolated ledger to insert a nonce.

The interface requires the explicit `BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST=enabled` CI-only flag. It contains no production SQL credentials or signer secrets, and any unknown pin, invalid receipt, bad raw body, revoked key or SQL failure stops the flow without returning sender trust.

### 3. Combined REAL loopback-to-PostgreSQL integration

`tests/mail-receiver-crypto-postgres-integration.test.mjs` opens the existing IPv4 `127.0.0.1` SMTP harness, sends synthetic raw email over a real socket, receives an ephemeral ECDSA-P256-signed receipt, looks up the synthetic receiver public key from PostgreSQL, validates the signature/raw MIME and commits the nonce in the disposable DB.

It then checks exact duplicate, tampered MIME before any additional DB write, and irreversible key revocation. This is end-to-end **within an offline synthetic environment**, not over the public internet.

### 4. Adversarial and concurrency tests

- `mail-verifier/tests/smtp-receiver-replay-policy.test.mjs`: 10 signed evidence and store-boundary checks
- `tests/fixtures/mail-receiver-replay-key-assertions.sql`: append-only immutability, public JWK restrictions, grants, key lifecycle, replay/digest conflict, stale/future cases and replacement key
- `tests/fixtures/mail-receiver-replay-concurrency.sh`: 24 independent concurrent psql processes
- `.github/workflows/bharatmail-receiver-replay-key-lifecycle-ci.yml`: two CI jobs only; no public SMTP listener, no Supabase deployment, no Netlify upload, no APK artifact, no secret provisioning

## Release blocker remains

A real receiving MTA with audited MX delivery, externally observed connecting SMTP IP, complete RFC support, trusted independent DNS, private key custody under KMS/HSM or equivalent, production-grade replay retention/expiry policy, managed rotation/incident response, operator identity and security/legal review is still **not** available. The existing Resend webhook verifies its event origin but not the external sender's SMTP envelope on its own.

Even an authentic SPF/DKIM/DMARC result authenticates domain behavior, not a person, organization officer, verified payment beneficiary, or safe request.

**Final disposition: SOURCE-ONLY / OFFLINE TEST CI PASS; LIVE SENDER VERIFIED = FALSE; ALL PRODUCTION AND ANDROID RELEASE GATES = HOLD.**
