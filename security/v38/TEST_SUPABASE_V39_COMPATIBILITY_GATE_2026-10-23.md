# V39 TEST enrollment compatibility gate — 23 Oct 2026
Status: SECURITY HOLD — audit only; NOT a deployment migration.

## Verified TEST database (project fsdusofbpwdrdvgexxyw)
- public.messaging_devices: id, user_id, device_label, public_key_jwk, key_algorithm, revoked_at, created_at, last_seen_at. RLS enabled.
- public.e2ee_v2_devices: device_id, user_id, signing_public_key, curve25519_public_key, protocol_version, created_at, last_seen_at, revoked_at. RLS enabled.
- bl_pairing_private.requests: id, user_id, candidate_public_key_jwk, candidate_label, challenge_nonce, status, expires_at, created_at, approved_device_id, approved_at. RLS enabled.
- bl_pairing_private.trust_anchors: device_id, user_id, signing_public_key, created_at. RLS enabled.
- bl_pairing_private.candidate_proofs and trust_challenges exist with RLS enabled.
- public.register_e2ee_v2_device(uuid,text,text) is SECURITY DEFINER, postgres-owned, search_path empty. It checks auth.uid(), key format and same-device conflicts; it does NOT verify a trusted-device approval signature, a bound candidate digest/nonce, or consume an approval receipt.

## Incompatibilities with V39 disposable reference
1. Reference requests use request_id/account_id/candidate_device_id/approver_device_id/candidate_key_sha256/nonce_sha256/expires_at_seconds/state. Existing pairing requests use id/user_id/candidate_public_key_jwk/challenge_nonce/status/expires_at; fields cannot be mapped by renaming alone.
2. Reference trusted anchors store verified, revoked_at and public_key_jwk; existing pairing trust anchors store signing_public_key but no verified/revoked_at. Do not assume existing anchors are verified.
3. Reference device and receipt writes are isolated private fixtures; deployed device records live in public.e2ee_v2_devices, and no equivalent consumed-approval receipt was verified.
4. First-device bootstrap and lost-device recovery must NOT be mistaken for existing-device approval. They need independent documented authority, rate limits and user-facing confirmation.
5. The currently callable registration RPC could bypass any new approval-only endpoint unless all registration paths are closed together. Do not revoke or replace it blindly: old clients and linked-device flows may depend on it.

## Mandatory release gates
- Read-only capture of all registration callers, RPC grants, table policies, constraints, triggers and client versions.
- Threat model and design for initial bootstrap, additional-device signed approval, recovery and revocation.
- Canonical transcript with account, candidate device ID, both public keys, approver device ID, nonce, expiry and single-use request ID; verify signature against server-established, non-revoked trust anchor.
- Atomic server-side lock + one-time consume + exact candidate insert + immutable receipt; reject replay, cross-account approval, key substitution, concurrent duplicate and rollback failure.
- Stage a migration in disposable Supabase-compatible PostgreSQL; test RLS and SECURITY DEFINER grants with anon/authenticated identities. Test existing clients for regressions.
- Explicit go/no-go after verified TEST migration and two-phone Android tests. Production remains untouched.

This document is an audit gate, not SQL to apply.

## Reconfirmed directly against TEST on 23 Oct 2026
Read-only pg_proc query independently reconfirmed `public.register_e2ee_v2_device(p_device_id uuid, p_signing_public_key text, p_curve25519_public_key text)` has `prosecdef=true` and `has_function_privilege('authenticated', oid, 'EXECUTE')=true`. This is an active legacy entrypoint, not merely an inferred compatibility risk. A broader follow-up function inventory was blocked by safety checks; no additional grants or entrypoints were verified in that attempt. Do not claim exhaustive caller/grant inventory.

### Mandatory cutover acceptance matrix (must run before TEST release)
| Case | Expected outcome |
| --- | --- |
| Existing authenticated client invokes legacy RPC after cutover | Denied, without creating a device |
| Unauthenticated user invokes new enrollment | Denied |
| Candidate provides approver key or `verified=true` | Denied; server retrieves verified trust anchor |
| Valid signed transcript from trusted non-revoked device | Exactly one enrollment and one receipt |
| Swapped candidate signing or encryption key | Denied |
| Wrong account, device, nonce, request or expiry | Denied |
| Revoked/unverified approver | Denied |
| Same approval replay or simultaneous reuse | At most one commit |
| Receipt insertion fails after device insert | Full rollback, request remains eligible for safe retry |
| First-device bootstrap and recovery | Explicit independent verified authority, never automatic approval |
| Existing Android and web clients | No silent fallback to legacy enrollment |

Release remains HOLD until these cases are demonstrated against staged TEST migration and physical devices. No changes to existing Supabase objects are authorized by this note.
