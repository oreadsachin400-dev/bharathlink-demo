# BharathLink Phase 7M — verified reviewer proof to evidence ledger

**5 November 2026 | Isolated offline and disposable CI | No live deploy**

## Purpose and threat

Phase7K verifies two synthetic independent P-256 reviewer signatures, but does not persist a review. Phase7L records one-time evidence digests under a private DB transaction; however, its privileged SQL function cannot independently prove that input digests represent valid signatures. An attacker who obtains a privileged database path could supply arbitrary well-formed hashes. Phase7M builds an **offline integration reference** that places Phase7K verification before Phase7L evidence staging, then tests the boundary end-to-end in **disposable PostgreSQL**.

This is not a production-proof authorization model: a real server must *enforce* the verification and receipt write within a trusted, independently audited transaction boundary. No real issuer or reviewer is currently provisioned.

## Changes

- `recovery-gate/verified-ledger-bridge.mjs` imports Phase7K cryptographic evidence verification, binds its exact account, session, request, challenge, device, candidate proof, issuer key, ECDH/signing key hashes and reviewer order to a separately trusted Phase7G governance intent; rejects conflicting evidence before constructing parameters.
- After **both reviewer ECDSA P-256 signatures verify**, it hashes each independently pinned reviewer public key's canonical coordinates, the **raw** ECDSA signature and the exact canonical signed payload, and returns the private Phase7L ledger's nine expected values.
- No SQL client, fetch, account token, secret signing key or storage calls exist in this bridge. The return status is `REVIEW_EVIDENCE_PREPARED_ONLY`, always `deviceApproved:false`, `deviceTrusted:false`, `canActivate:false`, `e2eeReady:false`, `enrollmentCommitted:false`.
- `tests/helpers/phase7m-synthetic-fixture.mjs` uses ephemeral in-memory synthetic P-256 reviewer keys. No private keys are exported to logs, database or repository.
- `tests/phase7m-verified-ledger-bridge.test.mjs` tests valid dual signature, digest format/canonical raw signature, mismatched user/session/request/challenge/device/proof/issuer/key/reviewer, invalid consent, revoked reviewer/issuer, swapped signatures, nonce/time tampering and absent cryptography.
- `tests/phase7m-pg-verification-bridge.mjs` tests a forged signature is blocked **before** storage, valid synthetic signatures produce one immutable review-only receipt, repeat replay is denied, and no trusted device is ever inserted.
- GitHub Actions runs existing Phase7I–L contract tests and disposable PG17 replay/race verification.

## Security limitations — still release blocking

- The source labelled `trustedCase`, `trustedIntent`, `trustedSession`, `reviewerRegistry`, `issuerRegistry` is **not automatically trusted** by naming. Each must be independently read and verified by a protected back end. Never accept these objects from client or user-editable JWT metadata.
- Phase7L staged owner-only SQL remains able to accept unverified hex digests if a privileged caller invokes it directly. This reference bridge is **not** an authorization gate for deployment. The future trusted service must remove bypasses, use least privilege, validate issuer/reviewer pins, verify and atomically consume signed evidence and nonce under DB lock, and externalize audit under independent controls.
- Real identity issuer/reviewer governance, personnel screening, two-person conflict checks, hardware key custody, recovery revocation, dispute resolution, anti-abuse rate limits and independently reviewed first-device bootstrap do not yet exist.
- Existing Android local E2EE keys cannot be reconstructed from server metadata or reviewer signatures. Historic ciphertext needs original compatible keys or a separately reviewed encrypted backup.
- Nothing in this phase signs or approves a first device, changes account login, decrypts mail, starts Android, updates production or modifies Supabase/Netlify.

## Release decision

**KEEP Draft / SECURITY HOLD.** PR is stacked on Phase7L, not main. Code/CI results must be checked explicitly, then independently reviewed. Real authority provisioning and actual two-phone E2EE acceptance remain external dependencies. This is a cryptographic integration test, not working account recovery.