# BharathLink Phase 7N — privileged hash ingress HARD STOP

**5 November 2026 | STAGED migration / disposable PostgreSQL CI | NOT DEPLOYED**

## Root cause and impact

Phase7K checks synthetic, independent ECDSA P-256 reviewer signatures. Phase7M produces hashed reviewer evidence only after verifying those signatures. Phase7L stores the resulting digests in a private, append-only PostgreSQL receipt. However, Phase7L's privileged owner-only function **accepts correctly formatted digests without checking the underlying signatures**. Therefore, the ordering proven in the Phase7M test harness is not a server-enforced authorization boundary: an attacker with that function's privileged execution context could bypass signature validation and manufacture an evidence receipt.

Phase7N closes the **ordinary privileged hash-only ingress path**, deliberately **disabling all further evidence receipt creation** while no real authoritative, independently reviewed server verifier exists. It does not implement, simulate, or approve recovery. This is a fail-closed staged replacement, not a production-ready user feature.

## Staged SQL

File: `sql/staged/TEST-phase7n-close-unverified-hash-ingress.sql`.

1. Uses `CREATE OR REPLACE FUNCTION` with the **same exact Phase7L signature** for `bl20_review_ledger_v1_private.stage_review_evidence`, returning SQLSTATE 42501 on every call. This prevents ordinary privileged callers from silently reaching the old hash-only logic through the same function signature.
2. Adds `BEFORE INSERT` hard-stop triggers for private receipt and event tables to reject a privileged caller's direct SQL INSERT, which could otherwise bypass the RPC.
3. Retains the prior append-only UPDATE/DELETE protection, existing historical receipts and audit rows. No device or E2EE table is touched.
4. Reaffirms no `PUBLIC`, `anon`, `authenticated`, or `service_role` execute permission for the legacy helper or newly added trigger function.

**Important limitation:** PostgreSQL owners and superusers with sufficient DDL privileges can replace functions, disable triggers or change tables. No SQL-only migration can cryptographically prevent a malicious all-powerful database administrator. A separated, independently audited trust service, real issuer/reviewer governance, trusted key custody and externally retained audit evidence are still mandatory.

## Validation

GitHub Actions uses disposable PostgreSQL 17 and synthetic account/reviewer data only. It creates one prior review-only receipt by running the Phase7M synthetic cryptographic verifier before installing Phase7N. Then it tests:
- old privileged hash helper denied even with valid-looking digests;
- direct owner INSERT into both receipts and audit events denied;
- already stored history remains immutable and present;
- restricted API roles lack schema/function access;
- two privileged concurrent SQL clients each rejected, with no new receipt;
- zero registered or approved devices;
- previous Phase7I–M source and cryptographic checks still pass.

The tests check this **staged design**. They do not validate compatibility with all real Supabase policies, migrations, GoTrue sessions, or Android installation state.

## Security gates still pending

- Real independent issuer and two credentialed reviewers, legal identity proofing, consent, conflict disclosure and accountability.
- HSM-backed or equivalent hardened key custody, revocation and out-of-band pinning.
- Authenticated server-only ingestion that **verifies signatures before any write**, with a separately reviewed, single-use nonce transaction and no exposed alternate privilege path.
- Privilege boundary review, service-role custody, immutable audit outside the database owner's sole control.
- Review of the entire Phase7I–N migration order and rollback plan.
- Correct original Android package signing continuity and historical E2EE key checks on both phones. Login alone cannot decrypt missing historic keys.

No account, key, chat, mail, RLS, Edge function, Android APK, Netlify TEST or production mutation was performed. Do not merge, deploy, uninstall, or reset encryption. **SECURITY HOLD** remains active.