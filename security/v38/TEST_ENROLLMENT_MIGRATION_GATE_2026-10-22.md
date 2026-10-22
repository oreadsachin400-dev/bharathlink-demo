# V38 TEST registration migration gate — 22 Oct 2026
STATUS: READ-ONLY AUDIT. NO DATABASE CHANGE AUTHORIZED BY THIS FILE.

## Confirmed from TEST PostgreSQL catalog
- public.register_e2ee_v2_device(uuid,text,text) is SECURITY DEFINER and executable by authenticated; it checks auth.uid and canonical public-key encoding but DOES NOT verify an existing trusted-device signature.
- authenticated does not have direct INSERT/UPDATE table privilege on public.e2ee_v2_devices.
- authenticated has direct INSERT privilege on public.messaging_devices; its policies and triggers must be reviewed as a distinct trust path.
- bl_pairing_private.requests and trust_anchors are RLS-enabled and not directly insertable by authenticated.
- V38's isolated handler and PostgreSQL adapter are reference code only. No deployed endpoint or matching private schema exists.

## Mandatory release blockers
1. Establish first-device bootstrap and account recovery authority separately; never allow the candidate to self-approve an existing account.
2. Map candidate Ed25519/P-256 signing-key formats and Curve25519 public key encoding to the V38 approval transcript. Never silently reinterpret key algorithms.
3. Define an authoritative pending request, nonce, expiry, key fingerprint, trusted approver identity and revocation check. Signature verification must be performed server-side.
4. Make approval consumption, receipt, and insertion into public.e2ee_v2_devices one database transaction, including concurrent/replay rejection.
5. Review all writers and policies for public.messaging_devices, public.e2ee_v2_devices and any SECURITY DEFINER wrappers. Closing only the browser test route is insufficient.
6. Implement a secure Android candidate/approver UX and a tested migration for existing devices, including locked-out recovery.
7. In disposable PostgreSQL, test positive enrollment, forged signature, cross-account, substituted keys, revoked approver, expiry, replay, rollback, and concurrent requests.
8. Only after a verified compatible replacement is staged should a TEST-only migration revoke legacy RPC EXECUTE and block bypass writes. Verify access under authenticated/anon and service contexts.
9. Keep production untouched. No deployment or live SQL should be inferred from CI green.

## Rollout decision
BLOCKED until the above gates are evidenced. This document is not a migration script.
