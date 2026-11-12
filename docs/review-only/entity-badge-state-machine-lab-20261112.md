# BharathLink — Final Verified Entity Badge State Machine (LAB ONLY)

**12 Nov 2026 | DRAFT / SECURITY HOLD | NO ACTIVE TEST OR PROD WRITES**

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

[Disposable GitHub PostgreSQL CI](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43243545162)
runs approximately **50 named security checks plus one real concurrent
per-account directory quota test**:
9 exact verified directory, 11 independent reviewer ledger,
9 publication preparation/revocation, 15 private final badge state tests,
6 search quota checks, and 1 two-session lock race.

The 15 new tests cover client inaccessibility, unprepared request,
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
  cross-entity endpoint claims. Their definitions have been inspected
  read-only, but these tests use a simplified synthetic fixture and do
  **not** establish live trigger/RLS/service-role compatibility.
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
