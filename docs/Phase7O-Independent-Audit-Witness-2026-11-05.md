# BharathLink Phase 7O — independent audit witness proof (STAGED ONLY)

**5 November 2026 | Isolated GitHub CI | No live Supabase/Android/Netlify changes**

## Why
Phase 7N's SQL hard stop denies ordinary privileged callers and normal INSERTs, but the database administrator/owner with sufficient DDL privileges can redefine functions, disable triggers and alter records. An audit log stored exclusively inside the same database cannot independently prove that a record was not changed.

Phase 7O adds an **offline verifier for a separately controlled P-256 digital signature** over an audit observation transcript. This is a testable design for tamper *detection*, not a database-owner-proof approval system. A real independent witness must observe and retain the event outside the database administrator's trust domain and sign only after independent verification. No such witness is provisioned today.

## Staged code
- `recovery-gate/independent-audit-witness.mjs`: strict, versioned domain-separated signed message with exact TEST project, case, governance intent, user, request, challenge, device, reviewer evidence digest, ledger receipt digest, audit-event digest, nonce, issuer, sequence, observed/expiry time and witness key ID.
- Pinned signer is accepted only from an independent **server-owned** witness registry; required role `external_audit_witness`, independent key custody, different operator from issuer, valid unrevoked key and valid P-256 coordinates.
- Uses WebCrypto ECDSA P-256 SHA-256 with raw 64-byte signature. Rejects wrong or malformed key/signature, modified record, stale/future or overlong statement, missing independent pin and wrong project ID.
- On valid synthetic signature returns `EXTERNAL_AUDIT_EVIDENCE_VALID_ONLY`; all activation flags remain **false**.
- `tests/phase7o-external-witness.test.mjs` creates ephemeral in-memory synthetic auditor keypairs and checks tamper/expiry/key trust/adversarial cases. No private key is committed or sent to any live service.
- CI is offline and runs previous Phase7I–N security regression tests.

## Mandatory security limits
This module **does not** verify legal identity, actual officer/reviewer role, old E2EE key possession, real Supabase session, or signed approval from a real independent issuer. It does not create an audit service, store receipts, establish append-only external record consistency, pin a real auditor or prevent a superuser from tampering with DB state. A signature only proves a key signed the exact statement; it does not guarantee that the statement is truthful or that a request is safe.

Before a real deployment, an independent entity must own and protect witness signing keys (separate from issuer and database administrators), implement witness-side policy, secure event capture, append-only externally retained log and consistency proofs, key rotation/revocation, incident handling and external audit. An observed sequence number alone is **not** replay prevention; independent ledger state and consistency checks are necessary.

No live device enrollment, payments, first-device trust or old-message decryption is enabled. The Phase7N hard stop remains the staged model; neither phase is applied to live TEST or production.

## Release
**KEEP DRAFT / SECURITY HOLD.** Existing encrypted phone keys and old messages must not be reset, overwritten or cleared. Independent issuer and two credentialed reviewers, server-only cryptographic verification and audit-coupled atomic authorization are still external dependencies. This phase is only a verified-audit-signature design checkpoint.