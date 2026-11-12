# BharathLink — Verified Entity Approval + Phone Search Quota
**12 November 2026 | SECURITY HOLD | REVIEW ONLY | NO LIVE DEPLOYMENT**

Disposable GitHub PostgreSQL 16 CI SUCCESS:
https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43167478947

26 named security test groups passed: 9 exact directory, 11 independent
review/audit, 6 quota; plus one real two-session row-lock concurrency test.
All users, organizations, phones and evidence hashes are fabricated.
No real account records, private phone searches or encryption keys read.

## Actual official TEST findings (read-only)
Supabase project fsdusofbpwdrdvgexxyw has entity_profiles,
entity_authorized_users, entity_verification_requests, entity_endpoints
and entity_endpoint_audit. It has protective triggers preventing direct
client changes to authoritative verification status, and a cross-entity
endpoint claim trigger. An independent reviewer provisioning/publication
RPC was not found. Aggregate counts: 0 entities, 0 verification
requests, 0 authorized entity members and 0 endpoints. No live changes.

## New files in draft PR #30
- sql/review-only/entity_dual_review_ledger_lab.sql
- tests/fixtures/entity_approval_lab_pg16.sql
- tests/entity_dual_review_contract.pgsql
- sql/review-only/directory_search_quota_lab.sql
- tests/directory_search_quota_contract.pgsql
- tests/run-directory-quota-race.sh
- updated .github/workflows/verified-directory-contract.yml

## Independent review ledger (not a Verified badge)
A private unexposed bl_directory_lab schema holds an approver registry
and append-only decision ledger. The registry is empty by default.
Real trusted reviewer onboarding is NOT implemented. Lab fixtures
insert synthetic reviewers to exercise proof-of-concept checks.

record_entity_evidence_review_v1 is a SECURITY DEFINER RPC whose EXECUTE
is revoked from PUBLIC, anon, authenticated and service_role in the
CREATE transaction. For a genuine caller authenticated via auth.uid():
- reviewer must be independently provisioned, active and within scope
- reviewer cannot be entity creator, requester or owner/admin/representative
- entity must remain pending; request must remain pending/in_review
- only a lower-case 64-character SHA-256 evidence reference is accepted
- each reviewer may submit exactly one irrevocable decision per request
- two different reviewers agreeing on same evidence hash return a
  review-complete-but-publication-still-blocked status
- reviewer disagreement and evidence hash mismatch require escalation
- the RPC NEVER updates entity or endpoint verification_status and
  NEVER mints a public Verified badge
- lab regression directly confirms audit rows cannot be updated or deleted

Distinct reviewer UUIDs do NOT prove independent people. An evidence hash
does NOT authenticate the evidence, official registry, government officer,
legal name, phone owner or bank account. Separate audited human-authority
provisioning, real evidence/source checks, reviewer revocation, appeal,
final server-only publication and audit-log retention are required.

## Rate-limited directory wrapper (not sufficient alone)
search_verified_directory_guarded_v1 adds account-level budget tracking
in a private, RLS-enabled table. Both it AND the underlying raw
search_verified_directory stay EXECUTE-denied to clients; temporary
test-only grants are revoked after tests.

Isolated PostgreSQL tests verify:
- 5 searches per minute per account and 50 per day (provisional policy)
- rejection rolls back quota transaction counters correctly
- different accounts have independent quotas
- raw directory search cannot bypass the gated wrapper
- two real parallel PostgreSQL sessions contend for one remaining
  daily slot: second visibly waits on the row lock and is denied

A real release also needs independent per-device/IP abuse controls,
per-account creation resistance, anomaly alerting, quotas across ALL
alternate directory endpoints, monitoring, appeals and retention limits.
Never indiscriminately log the numbers being searched. No actual Edge
gateway, published app integration or cleanup scheduler was built.

## Release blockers
1. Zero live verified entities: real registration, legal evidence and
   authorized independent verification must precede meaningful results.
2. Two-reviewer ledger is NOT a publication mechanism. The final
   authoritative badge/endpoint verification job does not exist.
3. The current SQL is review-only and not deployed; no public grants.
4. Other entity management, contact-point and directory RPCs are absent.
5. Published TEST frontend and official TEST Supabase differ; signer trust
   and two-physical-Android-device acceptance remain blocked.
6. Full real Supabase RLS, trigger concurrency, rate-limit abuse and
   provider API/Android integration were not exercised.

No TEST/PROD data, E2EE keys, sessions, Netlify deploy or APK changed.
