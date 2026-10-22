# TEST trusted-device enrollment — verified read-only findings

Scope: TEST Supabase project fsdusofbpwdrdvgexxyw. No migrations or writes performed.

## Observed catalog results
- PostgreSQL server version: 17.11.
- authenticated can EXECUTE public.register_e2ee_v2_device(uuid,text,text): true.
- public.messaging_devices has INSERT policy messaging_devices_insert_own, with_check (user_id = auth.uid()). Owner binding is not trusted-device approval.
- bl_pairing_private.requests columns: id, user_id, candidate_public_key_jwk, candidate_label, challenge_nonce, status, expires_at, created_at, approved_device_id, approved_at.
- bl_pairing_private.trust_anchors columns: device_id, user_id, signing_public_key, created_at.
- public.e2ee_v2_devices columns: device_id, user_id, signing_public_key, curve25519_public_key, protocol_version, created_at, last_seen_at, revoked_at.

## Blocking schema mismatch
The existing pairing request stores candidate_public_key_jwk but has no separately stored candidate E2EE signing key, X25519 key, or canonical combined-key digest. The V38 isolated approval transcript binds candidateKeySha256 and nonceSha256. Mapping a pairing approval to V2 enrollment without authoritative, immutable candidate key binding is unsafe.

## Required integration sequence (not implemented)
1. Review every direct table write path, function grant, trigger and current first-device bootstrap.
2. Stage an immutable candidate enrollment request with both canonical V2 public keys and a digest; server must derive digest and nonce hash.
3. Bind trusted approver identity to stored, unrevoked signing key and account; verify signature over canonical V38 transcript on server.
4. In one database transaction lock request and anchor, check pending/expiry/revocation, insert candidate device, consume request exactly once. Reject replay and cross-account attempts.
5. Design authenticated first-device bootstrap and lost-device recovery independently; no automatic trust based on OTP alone.
6. Test in disposable PostgreSQL and then isolated TEST with throwaway accounts. Only after successful negative and real Android tests, plan migration to close legacy RPC and direct INSERT bypass.
7. Do not deploy isolated branch index.html as onboarding replacement until flow works.

Security hold: NO production changes; NO TEST DDL, policy changes or APK release authorized by this audit.
