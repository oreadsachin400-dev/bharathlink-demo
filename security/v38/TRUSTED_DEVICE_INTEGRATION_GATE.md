# BharathLink trusted-device approval integration gate (TEST only)

Status: **BLOCKED / NOT DEPLOYED**. This is an integration contract, not an implemented production device approval flow. The isolated V38 PostgreSQL and offline P-256 tests do not authorize enrolling real devices.

## Boundaries
- Keep production main, production Supabase, and deployed TEST unchanged.
- Approval finalizer remains disabled; do not grant EXECUTE to anon/authenticated/service_role or expose private tables through client RPC.
- No auto-registration after missing E2EE key. Require explicit user action on the new device and explicit approval from an existing, verified, non-revoked device.
- Never put a signing private key, recovery secret, service-role token, or session credential in this repository, logs, URLs, or notification payloads.

## Required implementation sequence
1. Inventory the actual deployed TEST source for `register_e2ee_v2_device`, `allowNewDeviceRegistration`, `activateCurrent`, and the existing key-store lifecycle. Confirm TEST database schema and RLS against a read-only audit before proposing migration. Do not assume the offline V38 tables match deployed Supabase.
2. Define server-created, single-use approval request tied to account ID, candidate device ID, candidate signing-key SHA-256, approver device ID, nonce SHA-256, and expiry. Canonicalize with the versioned `approvalTranscript` reference. Bind every field to the signature.
3. Obtain explicit approval UI on a separately authenticated, already-trusted device. Verify P-256 SHA-256 signature against its pinned public key and enforce key status (verified, unrevoked), account equality, expiry, no self-approval, and replay resistance.
4. In one **server-side transaction**, atomically claim the pending request, verify authoritative stored fields and trusted-key status, write one receipt, enroll exactly one candidate device, and mark request approved. Unique constraints must reject concurrent duplicate approvals. The offline `authorizeApproval` Set is NOT a substitute for database atomicity.
5. Enforce denial on timeout, rejected/expired request, mismatched candidate key, revoked approver, stale session, or missing local E2EE key. Preserve existing E2EE messages and never silently replace device identity keys.
6. Test two physical Android devices in both directions, offline/background behavior, restart/session restoration, lost-device/recovery, and RLS negative cases. Review before any isolated TEST deployment.

## Promotion gates
- Disposable PostgreSQL CI green (including roles, replay, finalizer denial).
- Dedicated concurrent-transaction and real API/RLS integration tests green.
- Cryptographic transcript negative tests and hardware-backed key handling reviewed.
- Two-phone Android TEST acceptance green; explicit migration rollback plan.
- Independent security review before production activation.

**Until all gates pass, keep approval disabled and do not promote the branch to main.**
