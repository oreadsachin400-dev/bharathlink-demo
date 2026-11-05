# BharathLink Phase 7P — independently anchored audit checkpoint continuity

**5 November 2026 | Isolated TEST design, offline GitHub Actions | NOT DEPLOYED**

## Why this phase
Phase 7O verifies a synthetic independent audit witness's ECDSA P-256 signature over an observation. A **valid signature on one observation is not an append-only log**. A malicious operator could show another past signed statement, omit events, or present a fork of the log. Phase 7P adds an offline proof that a new signed checkpoint extends a **previous checkpoint retained independently outside the app and database administrator's control**.

The implementation is a **prototype verifier**, not an independent audit-witness service. No real external auditor or identity authority is provisioned.

## Cryptographic construction

File: `recovery-gate/witness-log-consistency.mjs`.

- The independently retrieved anchor must bind the exact BharathLink-20-TEST project, audit log ID, witness key ID, prior sequence and prior SHA-256 head.
- For each additional event, verify strictly consecutive positive sequence numbers. Compute the new head as SHA256 of a domain-separated UTF-8 tuple containing protocol ID, sequence, previous chain head and current event SHA-256. Limit the offline proof to 128 events.
- A candidate checkpoint specifies project/log/witness identity, old sequence/head, new sequence/head, issuance and expiry. Verify all bounds, freshness and the newly calculated chain head.
- Verify an ECDSA P-256/SHA-256 64-byte signature over the exact, versioned checkpoint using a **separately pinned witness verification key**. Reject absent, expired, revoked or role-conflicted witness registry entries.
- The output is **EXTERNAL_CHAIN_CONTINUITY_EVIDENCE_ONLY** with all activation fields false.

This proves that *given a genuine independent anchor and a genuine signing authority* the specified sequence of supplied event **hashes** matches the signed new head. It does not prove the events happened, that an issuer or two reviewers truly verified an identity, or that a user owns historic E2EE decryption keys.

## Threats covered in synthetic tests

The new `tests/phase7p-witness-log-consistency.test.mjs` creates ephemeral synthetic P-256 witness keys and tests valid proof, missing/non-independent anchor, changed or rolled-back sequence, conflicting prior head/log identity, event deletion/gap/reordering, modified event hash, altered checkpoint contents, forged or noncanonical signature, revoked witness, wrong project, expired/future checkpoints and missing crypto.

It runs together with existing Phase 7I–7O offline security tests in `.github/workflows/phase7p-witness-checkpoint-ci.yml`. No production credential, Supabase API or SQL mutation, Android APK or Netlify deploy is involved.

## What is still missing before real use

**1. An actual, independently accountable witness.** A DB-owned or client-provided `trustedAnchor` is not trusted even if it contains `externallyPinned:true`. A real auditor must independently collect evidence, apply policy and protect witness signing keys outside the database/issuer trust domain.

**2. Persistent anti-rollback and anti-fork state.** A hardened external service must store the most recently accepted checkpoint and enforce compare-and-swap (CAS) when advancing it. Independent publication/gossip/consistency monitoring is needed to detect split views among multiple clients. This module **does not** fetch or persist state, so it cannot by itself stop replay when a caller supplies a stale anchor.

**3. A trusted ingest/approval boundary.** The earlier Phase 7N SQL hash-ingress HARD STOP must remain in place until an independent server verifies reviewers and issuer credentials; no signature or audit chain should grant a device by itself. The existing staged SQL cannot stop a malicious database superuser with DDL privileges.

**4. Real-world governance and E2EE acceptance.** Independent issuer and two credentialed reviewers, key custody, consent, incident/revocation protocols, independent audit retention, secure Android package/signing continuity, and physical two-phone E2EE/key custody tests are necessary.

**Status: GitHub Draft / SECURITY HOLD.** Do not merge/deploy, create a fake trusted issuer or auditor, reset encryption, uninstall a key-bearing Android app, or imply that old messages have been recovered.