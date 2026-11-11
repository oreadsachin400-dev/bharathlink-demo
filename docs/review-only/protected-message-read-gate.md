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
