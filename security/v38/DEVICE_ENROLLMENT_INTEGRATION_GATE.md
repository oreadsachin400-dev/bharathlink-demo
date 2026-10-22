# Verified device enrollment integration gate (not enabled)

V38 offline P-256 checks and isolated PostgreSQL tests pass, but these are **not** authorization to enable device enrollment. The offline `authorizeApproval` reference uses an in-memory Set and explicitly does not guarantee atomicity. No production app or Supabase migration is made by this document.

## Required implementation contract

1. Candidate device generates its own non-exportable signing/encryption keys locally; never send private key material to a server. Associate a candidate key fingerprint and a random, single-use nonce with a short-lived request.
2. An already trusted, non-revoked device explicitly displays candidate identity and request context, and signs the exact versioned transcript defined in `approval_transcript.mjs`. Bind account ID, request ID, candidate and approver device IDs, candidate key SHA-256, nonce SHA-256 and expiry.
3. Server fetches the approver public key from an independently authenticated, authoritative trusted-device registry (never from candidate-submitted JWK). Reject self-approval, unknown/revoked keys, account mismatch, expired requests, reused nonce/request IDs, altered transcript and invalid P-256 signatures.
4. Perform cryptographic verification in a trusted server execution boundary, then execute a single database transaction with an authorization proof bound to the request, device and verified key. Do not accept a client-supplied `verified=true` flag or grant direct table writes.
5. The transaction must lock the pending request, enforce one-time use and uniqueness, atomically insert receipt and enrollment, and mark request consumed. Any error rolls back everything; duplicate or concurrent approvals must never enroll a second device.
6. Keep the SQL finalizer disabled until the server verification boundary, proof binding, transaction isolation and rollback tests are implemented and reviewed. RLS and schema grants must remain fail-closed.
7. Existing E2EE conversation keys must be shared only through an authenticated encrypted device-to-device transfer; enrollment by itself must not expose old messages. Provide explicit recovery/revocation paths without silently weakening E2EE.
8. Verify with two physical Android phones: first-device setup, candidate request, legitimate approval, altered identity/key/nonce/expiry, revoked approver, replay, simultaneous approvals, background app, failed network, and recovery. No automatic registration.
9. Use a separate disposable CI PostgreSQL instance and mock identities for integration testing. Do not target either existing Supabase project, deploy Netlify, or modify production main.

## Current status

- Offline reference verifier: CI-tested only.
- Isolated PostgreSQL schema/assertions: CI-tested only.
- Trusted server verifier + atomic enrollment: NOT IMPLEMENTED.
- Actual Android E2EE integration: NOT IMPLEMENTED.
- Production deployment: BLOCKED.

Release gate: no enrollment feature may be enabled until both server integration and device acceptance tests pass.
