# Manual Chat Read/Unread — Official TEST-compatible RPC candidate

**11 November 2026 | REVIEW ONLY | SECURITY HOLD | No live DB writes**

This draft addresses exactly two missing API names referenced by GitHub
main/index.html: mark_conversation_read(p_conversation_id uuid) and
mark_conversation_unread(p_conversation_id uuid).

## Read-only official TEST grounding

Official TEST: fsdusofbpwdrdvgexxyw. Confirmed:
- public.conversation_read_settings columns (user_id,conversation_id,
  manually_unread,updated_at), user/conversation composite PK.
- Existing get_conversation_read_state returns manually_unread (default false).
- Existing get_my_unread_conversations returns the current account's
  rows with manually_unread=true, ordered by updated_at.
- Existing get_conversation_unread_count counts message_receipts without
  read_at; this count is NOT the same as a manual unread flag.
- Existing mark_message_read writes message_receipts; the frontend calls
  it separately after mark_conversation_read when opening a chat.
- Existing direct-conversation blocked-peer predicate:
  bl_private.direct_conversation_blocked_for.
- Both mark_conversation_read and mark_conversation_unread are absent
  from official TEST public functions at the time of this review.

## Contract implemented

- Auth.uid() bound server-side; no caller user_id or role accepted.
- Explicit conversation membership AND block predicate checked.
- mark_conversation_unread sets only the current user's manual marker=true.
- mark_conversation_read sets only the current user's manual marker=false.
- Idempotent calls avoid updating the timestamp if the value is unchanged.
- Neither function modifies message_receipts, message ciphertext, history,
  encrypted device keys, contact directory or any other settings.
- Both public SECURITY DEFINER functions have explicit search_path='' and
  all-client EXECUTE REVOKED by default. SQL CREATE+REVOKE is ONE transaction.
- The disposable test harness temporarily grants authenticated EXECUTE
  to exercise behavior and then revokes it. No live permission granted.

## Verified in disposable PostgreSQL 16

14/14 checks PASS:
- default public/anon/authenticated access denied and direct table SELECT denied
- correct integration with actual TEST read state and unread-list getter definitions
- user-specific state (no changes to another chat member's marker)
- mark read vs unread exact boolean behavior and idempotent timestamps
- no change to underlying Seen/delivered receipt values
- no existing row safely initialized as read=false
- outsider, blocked peer, anonymous/missing account, NULL conversation ID
  and group member who has left all rejected
- client RPC EXECUTE remains denied after tests

## Explicit limits and release gates

- This does NOT mark individual peer messages read, clear real unread-count,
  or change Seen/delivery receipts. The app's separate per-message read flow
  must continue to work and be authenticated, avoiding false receipts.
- The real TEST blocked-user function has not been executed with actual
  users. The fixture uses a synthetic predicate to verify fail-closed
  behavior, not to claim full policy parity.
- The existing get_my_unread_conversations getter does not itself check
  direct-chat block status, so legacy manual markers may remain visible;
  independently audit that pre-existing read path before shipping.
- There may be simultaneous membership revocation and read-state changes;
  fully test concurrency/revocation in isolated staging before release.
- No signature/RLS acceptance against authenticated live Android accounts.
- This draft changes no published HTML, deployed Netlify site, mobile APK,
  Supabase TEST/PROD database, E2EE device keys, messages or user receipts.
- Do NOT merge/deploy the SQL or grant EXECUTE until the frontend/official
  TEST backend mismatch, signer enrollment and V1 release conditions pass.

Reference: Draft compatibility audit PR #28 and security hold issue #25.
The PHP/SQL/Node CI fixture contains only fabricated principals/messages
and metadata-only getter SQL definitions, not user content or secrets.
