# BharathLink — Protected View Once / disappearing read gate

**11 November 2026 — SECURITY HOLD — REVIEW-ONLY**

This branch introduces a candidate send_protected_encrypted_message_v2 contract
and disposable PostgreSQL 16 tests. It does **not** ship View Once or disappearing
messages. Do not run this DDL on active TEST or PROD or enable EXECUTE.

## Grounding

- Inspected actual official TEST definitions of send_encrypted_message_v2
  and get_my_encrypted_messages_v2_for_conversation without reading user rows.
- TEST has view_once_messages, disappearing_messages and a
  consume_view_once_message function, but no protected send RPC.
- TEST history RPC does not check view_once_messages.consumed_at or
  disappearing_messages.expires_at.
- Existing message_envelopes_select_own RLS checks recipient identity/device
  but not the protection metadata tables. Its direct API grants and
  client compatibility need explicit review.
- In disposable PostgreSQL 16, an authorized recipient twice obtained the same
  View Once wrapped key from the actual history RPC, before consumption.
  After changing a synthetic TTL record to expired, history still returned its
  wrapped key. See CI's EXPECTED RELEASE HOLD lines.

## Candidate scope (what has been proven)

The candidate wrapper:
- Reuses the actual existing sender RPC for authentication, ownership, device
  authorization, per-device coverage and duplicate-recipient rejection.
- Adds server metadata within the same DB transaction. Forced metadata
  trigger failure rolled back messages + envelopes + metadata.
- Accepts only actual client TTLs: 30 sec, 1 hour, 24 hours, 7 days, 90 days.
- Restricts View Once to direct conversations with exactly two distinct members,
  reflecting the current one-recipient-per-message metadata schema.
- Rejects missing protection mode, invalid TTLs, group View Once, outsider
  senders and malformed/duplicate device envelopes.
- Revokes EXECUTE from PUBLIC, anon, authenticated and service_role.
  The temporary authenticated GRANT in the test is confined to a disposable
  PostgreSQL job and revoked before the job exits.

These checks are not proof of the original full Supabase schema/triggers,
Edge functions, every frontend path, Media Storage, Android behavior or RLS.

## Required release work, in order

1. **Design a one-time decrypt-key claim contract**: authenticated owner,
   active authorized recipient device, direct-chat membership, row lock,
   first-claim-wins, replay rejection, cross-device concurrency, revoked
   device, blocked peer, independent device signing trust. Return the
   encrypted key material only through the claim. Client must not decrypt a
   protected message before the claim. Preserve legacy history safely.
2. **Close every alternate read route**: official history RPC, direct
   message_envelopes table API/RLS, Realtime, cached backup/restore,
   admin/service endpoints and media download flows. A claim gate is
   ineffective if a normal history RPC already returns the key.
3. **TTL enforcement even when cleanup is late**: deny expired wrapped keys
   in all read paths at read time; separately run and monitor trusted
   server-side envelope/key deletion and ciphertext/media lifecycle.
4. **Review media keys and copies**: encrypted media decryption keys may be
   carried in the message payload. Verify what's withheld until claim.
   Digital content already seen by recipients cannot be made uncopyable;
   don't promise absolute View Once against recording/saving.
5. **Actual two-Android-device test**: concurrent claim, restore/replay,
   message receipt, offline recovery, expiry, account switch and revoked
   signer. No delete/uninstall/reset of existing device keys.

## Explicit no-go

- No blanket GRANT EXECUTE on candidate RPC.
- No Supabase URL/publishable-key swap or raw SQL on active TEST/PROD.
- No fallback from protected send to ordinary send.
- No enabling View Once in frontend before read gate + device trust verified.
- No release claim from green disposable-sender CI alone.

## Evidence

Isolated CI: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/42980534576

Fixture intentionally simplified. The sender/history functions were captured
as code definitions from official TEST metadata only. It uses synthetic
users/devices and no real account, message content, JWT or secrets.


## 11 Nov update — isolated private key vault claim tests

**New evidence:** [GitHub PG16 isolated CI #43006222951](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43006222951) — SUCCESS.

- A new NON-EXPOSED schema, bl_protected_lab, holds E2EE-wrapped
  per-device message keys rather than public.message_envelopes.
  No authenticated/anon/service role has direct USAGE or SELECT.
- Client-callable-looking claim RPC is created **with EXECUTE revoked**.
  CI temporarily grants authenticated only in a disposable DB and re-revokes.
- Tests demonstrate first-claim-wins, repeat and cross-device denial,
  all alternate key copies erased on commit, expired TTL denied at read,
  unsigned, revoked, outsider, deleted-message and unauthenticated denial.
- Unsafe mixed public+private key storage is explicitly rejected. This
  means the already-existing protected-send wrapper (which uses the
  normal public-envelope sender) is **NOT** compatible with this claim
  approach and MUST NOT be released unchanged.
- A private, bounded, idempotent cleanup prototype erases expired vault
  envelopes and records purged_at, leaving unexpired envelopes intact.
  Cleanup is NOT connected to any real Supabase scheduler or storage job.
- A real two-PostgreSQL-session race under READ COMMITTED showed the
  second claimant waiting for the first row lock, then being rejected.
- Forced deletion failure rolled back the one-time consumed marker AND
  preserved both vault keys; a subsequent normal claim succeeded.
- No existing PROD/TEST data, keys, session, frontend, or database was
  modified. All test principals, messages and device IDs are fabricated.

### Architectural blockers remaining

1. Implement a NEW sender transaction that puts protected envelopes
   ONLY in the private vault (never normal message_envelopes), yet
   preserves sender device authorization, coverage and message indexing.
   Existing send wrapper is not that sender.
2. Provide metadata-only listing and verified, user-triggered claim UI;
   no cached decrypt-key payload via message Realtime, push,
   normal history, backups, or direct Data API.
3. Review all grants, private schema exposure, RLS policies, alternate
   endpoints, sensitive logs and SQL function ownership under real
   Supabase roles. Test actual signer-device revocation races.
4. Reconcile first-device signing trust: official TEST currently has
   zero trusted signer rows. The lab seeds invented verified signers,
   so it cannot prove real first-device enrollment or Android behavior.
5. Define loss-on-disconnect behavior: an atomic claim is consumed when
   the server commits, even if the HTTP response never reaches the
   client. A safe UX/recovery/ACK protocol requires separate review.
6. Ensure independent server-side purge, media key handling, storage
   lifecycle, cron failure handling, offline replay and two-physical-
   Android-device acceptance before any release.
7. No digital feature can guarantee a human cannot photograph/copy
   content they have already viewed. Communicate realistic limitations.

**Release guard stays active.** No claim RPC grants, app deployment,
merging, or real TEST schema writes are authorized by this CI result.


## 11 Nov — Key-free original-reader inbox (isolated)

[Disposable PG16 CI #43014011153](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43014011153) — SUCCESS.

New review-only files:
- sql/review-only/protected_metadata_inbox_lab.sql
- tests/protected_metadata_inbox.pgsql

**Design.** A private bl_protected_lab.authorized_readers index persists the
exact original recipients of each newly sent protected message.
The vault-only sender inserts this key-free index in the SAME
transaction as message metadata and private E2EE-wrapped keys. The index
has no direct role grants and is not in the exposed public Data API.

The new list_my_protected_messages_v1 RPC requires authentication,
an active signer-approved owned device, chat membership, non-blocked
conversation, original recipient-index membership and bounded keyset
pagination. Its output includes IDs, timestamp, state, and encrypted
message body/IV only while available. It NEVER returns an E2EE wrapped
device key, key wrapping IV, ephemeral JWK, signing key, or plaintext.

Consumed View Once and expired TTL items remain as key-free tombstones:
availability consumed/expired, ciphertext and IV returned as NULL.
This stays true if expiry cleanup runs late or has already erased keys.
The first View Once claim's deletion of vault keys does not delete the
original recipient index.

Verified on disposable PostgreSQL 16:
- Vault-only sender inserts key-free reader index atomically.
- Authorized original sender and recipient see message entries without
  keys; newly added group member cannot enumerate old protected entries.
- Non-member, unsigned/revoked device and account/device switch blocked.
- Synthetic direct-chat block predicate denies access; actual TEST
  function is not yet dynamically verified.
- Stable keyset pagination across 3 pages, bounded limits and no key leaks.
- Direct authenticated reader-table access denied; inbox RPC default
  EXECUTE denied before and after isolated test.

**Remaining release hold:** Existing TEST public.messages RLS may still
expose encrypted ciphertext (not the separated vault key) to chat members.
Every other read path, Realtime, backup, media and storage requires review.
Real TEST signer enrollment has no verified signing-key rows. No live
Android/client integration or response-loss/ACK recovery protocol exists
yet. An earlier candidate protected-send wrapper still writes keys to
public.message_envelopes; that candidate is INCOMPATIBLE with private
vault protection and must NOT be enabled. Do not deploy any part of
this draft branch to TEST/PROD without full release security review.
