# TEST E2EE enrollment write-surface verification — 23 Oct 2026

**Scope:** TEST Supabase project `fsdusofbpwdrdvgexxyw`. Read-only PostgreSQL catalog queries; no data or schema writes. This document is evidence, **not** permission to deploy or cut over.

## Observed directly from TEST catalog

| Object | Observation | Consequence |
|---|---|---|
| `public.messaging_devices` | RLS enabled; `authenticated` has effective INSERT table privilege, but no effective UPDATE privilege in the inspected role context | Existing owner-scoped INSERT policy can permit self-registration without proving trusted-device approval |
| `messaging_devices_insert_own` | INSERT policy `WITH CHECK (user_id = auth.uid())` | Ownership check alone is **not** cryptographic authorization |
| `messaging_devices_owner_update` | UPDATE policy uses `user_id = auth.uid()` for USING and WITH CHECK | Policy exists, but the effective UPDATE table privilege tested for `authenticated` was false; do not claim this path is writable without further verification |
| `public.e2ee_v2_devices` | RLS enabled; no effective INSERT or UPDATE table privilege for `anon`, `authenticated` or `service_role` in this catalog check | Direct authenticated table write not demonstrated; privileged definer/RPC paths still require review |
| `public.register_e2ee_v2_device(uuid,text,text)` | SECURITY DEFINER; `authenticated` has EXECUTE | Legacy callable registration entrypoint remains reachable |
| `public.messaging_devices` trigger | `trg_guard_messaging_device_update` is BEFORE UPDATE, invokes `guard_messaging_device_update()` | Does not establish any INSERT approval check |
| `public.e2ee_v2_devices` triggers | No noninternal trigger found by this inspection | Do not infer that function-mediated writes are safe |
| Both device tables | `relforcerowsecurity=false` | Definer/owner bypass considerations remain |

Other accessible SECURITY DEFINER functions discovered: `bl20_check_trusted_device`, `get_conversation_messaging_devices`, `is_my_messaging_device_active`. Their full definitions and call graph were **not** audited in this pass.

## Security conclusion

The TEST database still exposes two separate enrollment-related paths. `messaging_devices` ownership-based INSERT is not equivalent to server-verified existing-device authorization, and the legacy `register_e2ee_v2_device` RPC is executable. Do **not** describe either path as safely migrated. An UPDATE policy's presence must not be conflated with an effective UPDATE grant.

## Cutover order — fail closed without breaking existing accounts

1. Inventory and verify full definitions and callers of both registries, all SECURITY DEFINER writers, the UPDATE guard, and the existing app's read/registration flows.
2. Design and test first-device bootstrap and lost-device recovery as separate authority models. A candidate device must never self-approve as an existing trusted device.
3. Implement the server-side verified approval coordinator and a single atomic transaction for nonce consumption, receipt and registry insertion. Bind user, candidate signing/encryption keys, approver, expiry, and intended action.
4. Test against disposable PostgreSQL: success, replay, forged/expired approval, cross-account and key swap, revoked approver, concurrency, failed receipt/commit rollback, and existing-device compatibility.
5. Provide and verify Android candidate/approver UX and recovery before touching TEST grants.
6. In a staged TEST-only migration, close **both** bypass paths together: revoke legacy registration RPC EXECUTE and eliminate owner-only direct INSERT, after the replacement is demonstrably working. Audit all other writer paths.
7. Verify with actual role/JWT contexts and two physical phones. Only then consider a separate production change review.

**Release gate:** SECURITY HOLD. No TEST or production SQL changes performed. No claim of APK readiness or end-to-end E2EE security.
