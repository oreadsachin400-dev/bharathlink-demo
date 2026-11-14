# BharathLink — Final Verified Entity Badge State Machine (LAB ONLY)

**Updated 14 Nov 2026 | DRAFT / SECURITY HOLD | NO ACTIVE TEST OR PROD WRITES**

## What was built

Files:
- `sql/review-only/entity_badge_issue_revoke_lab.sql`
- `tests/entity_badge_issue_revoke_contract.pgsql`

A private, non-exposed `bl_directory_lab` PostgreSQL prototype now models
the **final organization Verified status** and **independent revocation**.
Unlike earlier publication-preparation-only stages, this candidate
does change public entity status in an **entirely disposable PostgreSQL
CI database containing synthetic records**. It has NEVER been installed
in the real BharathLink TEST or PROD Supabase project.

Candidate functions are SECURITY INVOKER, not public SECURITY DEFINER
RPCs, and have all client EXECUTE privileges explicitly REVOKED:
`bl_directory_lab.issue_verified_entity_lab_v1` and
`bl_directory_lab.revoke_verified_entity_lab_v1`. The lab authorizes
only `current_user='postgres'`; this is a **test trust boundary only**.
A real trusted service must independently authenticate and authorize
every actor, never trust arbitrary caller-supplied actor UUIDs, and use
a dedicated least-privilege role with audited credential custody.

## Verified issuance contract

Before an organization becomes Verified:
- An entity and still-open original verification request must be pending.
- The same request must have current, non-revoked private publication
  preparation completed in the last seven days by another approver.
- Exactly two distinct, active and properly scoped reviewers must have
  approved the same evidence SHA-256 reference without disagreement.
- An independent authority attestation must match the evidence and not
  be expired. Issued badge expiry may not exceed the evidence expiry
  or the provisional 90-day certificate cap.
- Final publisher must be active and independent from requester,
  organization creator/members, preparer, reviewers and attester.
- The official source-reference SHA-256 is permanently unique in the
  private issuance ledger; two entities cannot silently reuse it,
  even after revocation.
- Issuance atomically writes the organization Verified status,
  request approval, private issuance record and immutable event.
- **Every phone, email, UPI and other entity endpoint remains separately
  pending/unchanged**. Organizational verification never auto-verifies
  a phone number.

## Verified revocation contract

A separate active publisher, not the original issuer/preparer,
organization owner or requester, must record a meaningful reason.
The same transaction changes entity status to revoked and
**cascades existing verified/suspended endpoint statuses to revoked**,
including per-endpoint revoked_at, revoked_by and immutable audit event.
Another entity's endpoints remain untouched.
If any audit write fails, both status changes and endpoint updates
roll back. Same badge cannot be reissued with the old request or revoked
twice.

## Tests

[Disposable PostgreSQL 16 CI — 14 Nov, 53 PASS](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43604915899)
includes 9 verified-directory, 11 independent-reviewer, 9 private
publication-preparation, **17 badge/real-trigger compatibility**, 6 search
quota checks, and 1 real two-session concurrent quota-lock race.

In addition to the prior 15 badge state checks, the harness now replays
**exact read-only snapshots of three official TEST trigger definitions**
in the synthetic PostgreSQL fixture:
`protect_entity_verification_fields`,
`protect_entity_endpoint_verification_fields`, and
`trg_prevent_cross_entity_endpoint_claim`.
Two new checks demonstrate that the captured trigger bodies reject
simulated authenticated client writes to entity/endpoint verification
status, and block a second organization claiming an already verified
normalized phone number. End-to-end synthetic issuance/revocation and
all previous checks pass with these same trigger bodies installed.

Files added/updated:
- `tests/fixtures/entity_live_verification_triggers_pg16.sql` — source snapshot
  from **official TEST read-only inspection on 14 Nov**, with a tiny
  `auth.role()` GUC stub and missing synthetic audit fields.
- `tests/entity_badge_issue_revoke_contract.pgsql` — added 2 trigger checks.
- `.github/workflows/verified-directory-contract.yml` — loads fixture
  before badge tests, never points at any live database.

The original 15 tests cover client inaccessibility, unprepared request,
preparer/reviewer/requester separation, certificate expiry, altered evidence,
atomic issuer rollback, organization-only publication, repeat issuance,
duplicate registry identity, independent revocation, revocation rollback,
endpoint cascade and preservation of other organizations, no silent
reactivation, immutable audit and no final client privileges.

## Significant limits — do NOT treat lab PASS as a real Verified badge

- Synthetic SHA-256 evidence and official registry reference hashes are NOT
  evidence that a real legal authority has been consulted. No live source
  connector, signed attestation, evidence custody, human-review identity
  proof or judicial/organizational verification was implemented.
- A privileged database caller could spoof the `p_actor` argument.
  A real service must bind actor identity to verified operator session
  and enforce multi-person separation outside SQL.
- Actual TEST has triggers guarding verification fields and preventing
  cross-entity endpoint claims. **Those three actual trigger function
  bodies are now replayed verbatim** in a simplified PostgreSQL 16
  fixture; this strengthens **logic compatibility**, but still does
  **not** establish live schema, grants, RLS, service-role permissions,
  auth runtime, transaction isolation or migration compatibility.
  Fixture's `auth.role()` is a stand-in, not real Supabase Auth.
- The existing TEST trigger implementation only checks client auth.role
  to block verification mutations; it is not a complete authorization
  system for a privileged publisher. The final deployment would require
  a dedicated, audited trust service and stronger release controls.
- No independently audited endpoint issuance flow or actual endpoint
  verification source check exists. Revocation cascade is tested only.
- SQL candidate is NOT a deployable migration. Both functions remain in
  a private schema with no client usage/EXECUTE grants; PR stays draft.
- Main frontend/official TEST Supabase mismatch, first-device E2EE signer
  bootstrap, onboarding, rate-limit gateway and two Android devices
  remain independent, active release blockers.

**No actual TEST/PROD entity was changed, no badge issued, no E2EE key
or conversation touched, and no Netlify/APK deploy was performed.**
