# V39 TEST enrollment RPC — verified read-only security gate (2026-10-23)

Source: read-only TEST Supabase pg_proc query, not inferred from CI.

- Function: public.register_e2ee_v2_device(uuid,text,text).
- SECURITY DEFINER: true; explicit EXECUTE grant to authenticated.
- Uses auth.uid() and canonical public-key validation, conflict protection and revocation check.
- Does NOT require trusted approver, signature, signed immutable request, nonce, receipt or single-use consumption before INSERT into public.e2ee_v2_devices.
- Therefore adding private V39 tables alone does NOT close the enrollment bypass.

## Required before any TEST migration
1. Implement server-controlled verified approver provenance and signature verification (not a client-supplied verified flag).
2. Bind signed transcript to account, candidate ID, both candidate keys, request nonce and expiry.
3. Atomic DB transaction: lock request and anchor, verify approval, insert device, consume request, insert unique receipt; rollback on any failure.
4. Cut over ALL client enrollment entrypoints, and revoke/replace legacy authenticated EXECUTE in same controlled migration; validate old route fails and new route succeeds only with valid signature.
5. Explicit separate first-device bootstrap and recovery flow. No silent auto-enrollment.
6. Test Android Phone 1 and Phone 2 with rollback plan, no production changes.

## Release gate
HOLD: do not deploy V39 schema or enable registration until above conditions and CI/device tests pass. This document does not assert implementation or security approval.

## Confirmed direct messaging device write path
TEST read-only permissions check: authenticated role has INSERT privilege on public.messaging_devices, but not on public.e2ee_v2_devices. Policy messaging_devices_insert_own checks user_id = auth.uid(); messaging_devices_owner_update permits owner updates. This is a separate registration surface that must be covered by cutover and compatibility tests. Do not change live grants until caller inventory and first-device flow are ready.
