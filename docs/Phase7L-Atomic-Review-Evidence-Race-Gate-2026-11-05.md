# BharathLink Phase 7L — Atomic signed-review evidence ledger (STAGED ONLY)

**5 November 2026 | Offline and disposable Postgres CI | NOT DEPLOYED**

## Why this phase exists
Earlier Phase 7K checked *two distinct synthetic ECDSA P-256 reviewer signatures* and confirmed exact reviewer, issuer, account, device, challenge, nonce, key and expiry binding. It deliberately returns review-evidence-only, not approval. However, two parallel consumers of the same evidence could still try to record or reuse it unless there is a server-atomic replay barrier. Phase7L adds that specific barrier as a **private, non-authorizing ledger**.

## Implementation
- `sql/staged/TEST-phase7l-review-evidence-ledger-v1.sql`: private schema `bl20_review_ledger_v1_private`, evidence-only receipt and append-only event table, unique constraint on intent/request/challenge/device/nonce, immutable update/delete triggers, explicit RLS and grants revoked from PUBLIC/anon/authenticated/service_role.
- `stage_review_evidence`: owner-only, SECURITY INVOKER, locks Phase7G governance intent `FOR UPDATE` and rejects vetoed, stale, missing or mismatched intent, expired auth session, malformed/doubled reviewer signature/key digests, expired evidence and replay. One transaction inserts the receipt and audit event. Every successful return explicitly reports deviceApproved/trustedDevice/e2eeReady/enrollmentCommitted/canActivate **false**.
- `tests/fixtures/phase7l-disposable-governance.sql`: synthetic minimal fixture mirroring the Phase7G fields this ledger reads. It does not establish compatibility with every existing live DB dependency.
- `tests/fixtures/phase7l-ledger-denials.sql`: direct disposable Postgres negative tests for privileges, replay, cross-intent nonce, duplicate key, expiry, issuer/governance veto, stale session and history immutability.
- `tests/phase7l-racing-receipt.mjs`: two independent SQL clients compete for the same intent and nonce; exactly one evidence-only receipt must persist, with **zero** device registration rows.
- `tests/phase7l-ledger-contract.test.mjs`: static no-approval boundary and Phase7G expected-column checks.
- `.github/workflows/phase7l-review-ledger-race-ci.yml`: read-only source checks and disposable PostgreSQL 17 service, with no live network credentials or deployment steps.

## Security limits (mandatory)
This is **not an operational recovery authorization transaction**. A SHA-256 digest of a claimed reviewer signature, even two such digests, does not prove the corresponding private-key signatures were validated or that real reviewer roles were independently credentialed. The SQL trusts only the *existing synthetic governance intent* and is private to a privileged migration owner for CI. Real release requires separate trusted server verification and an independent review of atomic binding and key custody. Database superusers can alter triggers, so external oversight and immutable audit separation are also required.

No real issuer or authentic reviewer is provisioned. No legitimate first trusted signer is established. The Phase7I DB HARD HOLD remains staged and absent on BharathLink-20-TEST. Old encrypted chats still require original keys or an approved encrypted backup; account login cannot recreate those keys.

## Release criteria
1. Real independent accountable issuer plus two independently approved reviewers, documented consent and KYC evidence standards.
2. Protected issuer and reviewer key registry, revocation/rotation and external independent audit.
3. Signature validation on **server-owned** canonical payload with client-id spoofing protection, enforced rate limits, freshness, retries, and exactly-once signed case/nonce consumption. This staged evidence receipt alone is never authorization.
4. Review of full Phase7G/H/I/J/K/L schema migration sequence, rollback and default privilege interactions, and abuse testing against privileged legacy approval.
5. Android signing-key continuity, existing local E2EE key safety, and physical Sachin/Nidhi two-phone acceptance tests before any APK release.
6. Keep all Draft PRs unmerged and TEST/production unchanged until security approval.

**Status: evidence replay/race design implemented for disposable CI; NOT merged or deployed.**