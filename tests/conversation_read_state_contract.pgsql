\set ON_ERROR_STOP on
\echo 'ISOLATED PG16 MANUAL READ-STATE CONTRACT — TEST DATA ONLY'

INSERT INTO public.conversations(id,conversation_type) VALUES
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','direct'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','group'),
('ffffffff-ffff-4fff-8fff-ffffffffffff','direct');
INSERT INTO public.conversation_members(conversation_id,user_id) VALUES
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','11111111-1111-4111-8111-111111111111'),
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','22222222-2222-4222-8222-222222222222'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','11111111-1111-4111-8111-111111111111'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','22222222-2222-4222-8222-222222222222'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','33333333-3333-4333-8333-333333333333'),
('ffffffff-ffff-4fff-8fff-ffffffffffff','22222222-2222-4222-8222-222222222222');

INSERT INTO public.messages(id,conversation_id,sender_id) VALUES
('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd','22222222-2222-4222-8222-222222222222');
INSERT INTO public.message_receipts(message_id,user_id,delivered_at,read_at)
VALUES (
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 '11111111-1111-4111-8111-111111111111',
 '2026-10-01T00:00:00Z',
 NULL
);

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN
  RAISE EXCEPTION 'Unreleased unread RPC was callable';
 END IF;
 blocked:=false;
 BEGIN PERFORM public.mark_conversation_read(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN
  RAISE EXCEPTION 'Unreleased read RPC was callable';
 END IF;
 blocked:=false;
 BEGIN PERFORM 1 FROM public.conversation_read_settings;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN
  RAISE EXCEPTION 'Direct table SELECT should be denied';
 END IF;
END $deny$;
RESET ROLE;
SET ROLE anon;
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Anonymous called unread RPC'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: No client EXECUTE or direct read-state table access by default.'

-- Exercise candidates only inside disposable PostgreSQL 16.
GRANT EXECUTE ON FUNCTION public.mark_conversation_unread(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.mark_conversation_read(uuid) TO authenticated;

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.mark_conversation_unread('dddddddd-dddd-4ddd-8ddd-dddddddddddd');
DO $check$
BEGIN
 IF public.get_conversation_read_state(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd') IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Existing getter disagrees with new mark-unread';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM public.get_my_unread_conversations() r
  WHERE r.conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd') THEN
  RAISE EXCEPTION 'Existing unread-list getter missing new marker';
 END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Mark unread agrees with actual TEST read-state/list getter APIs.'

-- Other recipient must not be marked unread by first user's operation.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
BEGIN
 IF public.get_conversation_read_state(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd') IS DISTINCT FROM false
 THEN RAISE EXCEPTION 'Another member inherited caller unread flag'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Manual unread marker is per-user, never copied to peer account.'

-- Explicitly preserve stable updated_at for repeated identical operations.
UPDATE public.conversation_read_settings SET updated_at='2025-01-01T00:00:00Z'
WHERE conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd'
 AND user_id='11111111-1111-4111-8111-111111111111';
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.mark_conversation_unread('dddddddd-dddd-4ddd-8ddd-dddddddddddd');
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT updated_at FROM public.conversation_read_settings
  WHERE user_id='11111111-1111-4111-8111-111111111111'
   AND conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd')
   <> '2025-01-01T00:00:00Z'::timestamptz THEN
  RAISE EXCEPTION 'Repeated unread modified updated_at unnecessarily';
 END IF;
END $check$;
\echo 'PASS: Idempotent mark-unread does not mutate last-state-change time.'

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.mark_conversation_read('dddddddd-dddd-4ddd-8ddd-dddddddddddd');
DO $check$
BEGIN
 IF public.get_conversation_read_state(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd') IS DISTINCT FROM false
 THEN RAISE EXCEPTION 'Manual unread flag not cleared'; END IF;
 IF EXISTS (SELECT 1 FROM public.get_my_unread_conversations()
  WHERE conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd') THEN
  RAISE EXCEPTION 'Manually read chat still in unread-list';
 END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Mark-read clears only the manual flag in existing getters.'

-- Receipt must not be changed by Mark Conversation Read. UI already calls
-- mark_message_read separately for individual received messages.
DO $check$
BEGIN
 IF (SELECT read_at FROM public.message_receipts
  WHERE message_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    AND user_id='11111111-1111-4111-8111-111111111111') IS NOT NULL THEN
  RAISE EXCEPTION 'Conversation-level read wrongly set message Seen receipt';
 END IF;
 IF (SELECT delivered_at FROM public.message_receipts
  WHERE message_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    AND user_id='11111111-1111-4111-8111-111111111111')
    <> '2026-10-01T00:00:00Z'::timestamptz THEN
  RAISE EXCEPTION 'Conversation-level action changed delivery timestamp';
 END IF;
END $check$;
\echo 'PASS: Read/unread actions do NOT mutate message Seen or delivered receipts.'

-- A second identical read must not mutate updated_at either.
UPDATE public.conversation_read_settings
 SET updated_at='2025-02-02T00:00:00Z'
 WHERE user_id='11111111-1111-4111-8111-111111111111'
   AND conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.mark_conversation_read('dddddddd-dddd-4ddd-8ddd-dddddddddddd');
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT updated_at FROM public.conversation_read_settings
  WHERE user_id='11111111-1111-4111-8111-111111111111'
    AND conversation_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd')
   <> '2025-02-02T00:00:00Z'::timestamptz THEN
  RAISE EXCEPTION 'Repeated read modified stable updated_at';
 END IF;
END $check$;
\echo 'PASS: Idempotent mark-read preserves timestamp.'

-- An initially unread=false chat with no settings gets a false row.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.mark_conversation_read('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
DO $check$
BEGIN
 IF public.get_conversation_read_state(
 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee') IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'New settings false initialization failed'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Mark-read is safe with no pre-existing user settings row.'

-- Outsider must not write either state for another conversation.
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Outsider set manual unread'; END IF;
 blocked:=false;
 BEGIN PERFORM public.mark_conversation_read(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Outsider reset another user flag'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Non-member cannot change conversation manual read/unread state.'

-- An existing member must also be blocked when direct-chat block state
-- says unavailable. Synthetic blocker logic only; live block RPC separate.
SET bhl.lab.blocked_uid='22222222-2222-4222-8222-222222222222';
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Blocked peer marked unread'; END IF;
 blocked:=false;
 BEGIN PERFORM public.mark_conversation_read(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Blocked peer marked read'; END IF;
END $deny$;
RESET ROLE;
RESET bhl.lab.blocked_uid;
\echo 'PASS: Blocked direct-chat member cannot update either marker.'

-- Anonymous JWT context even when temporary grant exists fails auth.uid().
SET ROLE authenticated;
RESET request.jwt.claim.sub;
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Missing auth accepted'; END IF;
 blocked:=false;
 BEGIN PERFORM public.mark_conversation_read(
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Missing auth accepted for read'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Missing authenticated account fails both APIs closed.'

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(NULL::uuid);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'NULL unread id accepted'; END IF;
 blocked:=false;
 BEGIN PERFORM public.mark_conversation_read(NULL::uuid);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'NULL read id accepted'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: NULL conversation ID fails closed without writes.'

-- Leaving group invalidates previously authorized writes.
DELETE FROM public.conversation_members
WHERE conversation_id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
 AND user_id='33333333-3333-4333-8333-333333333333';
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.mark_conversation_unread(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Left member marked group unread'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Left group member cannot modify the old group marker.'

-- Restore default fail-closed grants after test.
REVOKE EXECUTE ON FUNCTION public.mark_conversation_unread(uuid)
 FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.mark_conversation_read(uuid)
 FROM authenticated;
DO $check$
BEGIN
 IF has_function_privilege('authenticated',
   'public.mark_conversation_unread(uuid)','EXECUTE')
    OR has_function_privilege('authenticated',
   'public.mark_conversation_read(uuid)','EXECUTE') THEN
  RAISE EXCEPTION 'Test left release candidate enabled';
 END IF;
END $check$;
\echo 'PASS: Client EXECUTE denied for both RPC candidates after tests.'
