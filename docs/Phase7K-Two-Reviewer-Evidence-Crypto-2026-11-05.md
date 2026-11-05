# BharathLink Phase 7K — two-person signed recovery review evidence

**5 November 2026 | TEST-only, offline cryptographic verifier | NOT DEPLOYED**

## Engineering change
This phase addresses a specific missing proof between proposed independent identity review and device enrollment. Phase 7J confirmed the BharathLink-20-TEST database has **zero independently verified signing keys and zero trust anchors**, with first-device hard-stop SQL still staged (not installed). Existing Phase 3/5 independently signed issuer-review gate uses two reviewer IDs, but those IDs alone do not cryptographically prove two independently credentialed people consented to the same request.

The new module `recovery-gate/dual-review-evidence.mjs` verifies **two separate raw ECDSA P-256 signatures** over a domain-separated canonical statement. Each reviewer signs the exact user/account, session, case, request, challenge, proposed device ID, candidate proof ID, ECDH/signing key fingerprints, evidence digest, issuer pin, nonce digest, owner consent and issuance/expiry. The statement is explicitly **review evidence only**, not device approval.

Both reviewers must be distinct, independently credentialed, active, unrevoked, within validity, have different provisioned signing keys and independent separation groups, have no listed conflict with the account owner, and hold the exact `FIRST_DEVICE_REVIEW_EVIDENCE_ONLY` role scope. It must be paired with an independently pinned, unrevoked issuer-key fingerprint and independently validated GoTrue-authenticated account/session, fresh consent, unused challenge and proven candidate key possession.

Review records, issuer pins and reviewer keys **must originate from authenticated server-side sources**, never from the mobile client. The module is deliberately not a transport/API service. Its output, even on valid synthetic signatures, sets `canActivate:false`, `deviceApproved:false`, `e2eeReady:false` and `enrollmentCommitted:false`.

## Limits / blockers
- No real issuer, real reviewer, reviewer trust registry, independent identity-proving organisation or cryptographic custody infrastructure is established.
- The module **does not** issue reviewer keys, create trust anchors, provision identities, enroll devices, reset E2EE, read old chat histories, query Supabase, or consume replay nonces.
- A live operational flow needs **separate audited identity evidence**, independent governance, hardware-protected issuer/reviewer credentials, nonce consumption, immutable review events, per-request rate limiting, revocation propagation, reconciliation and a single atomic server commit after security review.
- Two signatures can both be supplied by an attacker if the key registry is attacker-controlled. Pinned keys must be provisioned out-of-band by a real accountable organisation; role records or IDs alone have no standing.
- Login or OTP is not independent first-device authorisation.
- Phase7I SQL hard-stop is only staged, not installed in live TEST. Do not merge staged branches into production without explicit security architecture review and a rollback plan.

## Testing
`.github/workflows/phase7k-dual-review-evidence-ci.yml` runs synthetic ECDSA P-256 cryptography with domain-separated evidence payloads, wrong account/key/challenge/nonce/reviewer proof, swapped signatures, expiry, conflict, revoked issuer/reviewer and forged status negatives. Includes prior Phase7I/J HOLD suites and the existing Phase 3 independent-review tests.

No real user account, real verification document, payment, APK, Netlify deploy, live SQL or Supabase secret is used. No production or existing Android key state is changed.

## Next release criteria
1. Commission real independent identity issuer and governance with two accountable reviewers and auditable evidence policies.
2. Review and pin issuer/reviewer verification keys in a **server-owned** registry, with external security controls and revocation.
3. Implement a separate authenticated, rate-limited review intake and a **server-atomic, single-use challenge transaction**. This verifier alone must never grant activation.
4. Validate Android package signing continuity and existing local E2EE keys **without deleting or exporting** them. Restore historic chats only when valid old key access is independently established.
5. Physical two-phone (Sachin/Nidhi) acceptance, then release approval. Until then **SECURITY HOLD**.

**Status: cryptographic reviewer evidence verification only. Not a deployed recovery solution.**