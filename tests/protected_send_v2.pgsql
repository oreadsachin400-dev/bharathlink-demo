\set ON_ERROR_STOP on
\echo 'ISOLATED POSTGRESQL 16 TEST ONLY — no remote Supabase connections'
INSERT INTO public.conversations(id,conversation_type) VALUES
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','direct'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','group');
INSERT INTO public.conversation_members(conversation_id,user_id) VALUES
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','11111111-1111-4111-8111-111111111111'),
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','22222222-2222-4222-8222-222222222222'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','11111111-1111-4111-8111-111111111111'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','22222222-2222-4222-8222-222222222222'),
('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','33333333-3333-4333-8333-333333333333');
INSERT INTO public.messaging_devices(id,user_id,public_key_jwk) VALUES
('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','11111111-1111-4111-8111-111111111111','{"kty":"EC","crv":"P-256"}'),
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','22222222-2222-4222-8222-222222222222','{"kty":"EC","crv":"P-256"}'),
('cccccccc-cccc-4ccc-8ccc-cccccccccccc','33333333-3333-4333-8333-333333333333','{"kty":"EC","crv":"P-256"}');
CREATE FUNCTION public.test_envelopes() RETURNS jsonb LANGUAGE sql IMMUTABLE AS $test$
 SELECT pg_catalog.jsonb_build_array(
 pg_catalog.jsonb_build_object('recipient_user_id','11111111-1111-4111-8111-111111111111','recipient_device_id','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ciphertext','wrapped-a','iv','iv-a','eph_pub',pg_catalog.jsonb_build_object('kty','EC'),'encryption_version',2),
 pg_catalog.jsonb_build_object('recipient_user_id','22222222-2222-4222-8222-222222222222','recipient_device_id','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','ciphertext','wrapped-b','iv','iv-b','eph_pub',pg_catalog.jsonb_build_object('kty','EC'),'encryption_version',2)
 );
$test$;

-- An installed but unreleased RPC MUST be inaccessible without role grants.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
BEGIN
  BEGIN
    PERFORM public.send_protected_encrypted_message_v2(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'ffffffff-ffff-4fff-8fff-fffffffffff0','ct','iv',
      public.test_envelopes(),NULL,true
    );
    RAISE EXCEPTION 'Unexpected execution before release grant';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$deny$;
RESET ROLE;
SET ROLE anon;
DO $deny$
BEGIN
  BEGIN
    PERFORM public.send_protected_encrypted_message_v2(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'ffffffff-ffff-4fff-8fff-fffffffffff0','ct','iv','[]'::jsonb,NULL,true
    );
    RAISE EXCEPTION 'Anonymous call unexpectedly authorized';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$deny$;
RESET ROLE;
\echo 'PASS: No default anonymous or authenticated EXECUTE.'

-- TEST-ONLY grant for exercising candidate SQL in disposable database.
-- Never copy this GRANT into release migration.
GRANT EXECUTE ON FUNCTION public.send_protected_encrypted_message_v2(
  uuid,uuid,uuid,text,text,jsonb,integer,boolean
) TO authenticated;

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
-- Direct View Once: normal sender validates both envelopes, atomic metadata.
SELECT public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff1','ciphertext-1','iv-1',
 public.test_envelopes(),NULL,true
) AS protected_id;
RESET ROLE;
DO $check$
BEGIN
  IF (SELECT count(*) FROM public.messages) <> 1 THEN
    RAISE EXCEPTION 'View Once message not inserted once';
  END IF;
  IF (SELECT count(*) FROM public.message_envelopes WHERE message_id=(SELECT id FROM public.messages WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff1')) <> 2 THEN
    RAISE EXCEPTION 'Device envelope coverage failed';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.view_once_messages
    WHERE message_id=(SELECT id FROM public.messages WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff1')
      AND sender_id='11111111-1111-4111-8111-111111111111'
      AND recipient_user_id='22222222-2222-4222-8222-222222222222'
      AND consumed_at IS NULL
  ) THEN RAISE EXCEPTION 'Server View Once metadata missing or incorrect'; END IF;
END
$check$;
\echo 'PASS: Atomic View Once send records exactly one direct recipient.'

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff2','ciphertext-2','iv-2',
 public.test_envelopes(),30,false
) AS ttl_id;
RESET ROLE;
DO $check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.disappearing_messages
    WHERE message_id=(SELECT id FROM public.messages WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff2') AND ttl_sec=30
      AND expires_at BETWEEN pg_catalog.clock_timestamp()+interval '15 seconds'
                         AND pg_catalog.clock_timestamp()+interval '40 seconds'
  ) THEN RAISE EXCEPTION 'TTL registration missing or invalid'; END IF;
  IF EXISTS (SELECT 1 FROM public.view_once_messages WHERE message_id=(SELECT id FROM public.messages WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff2')) THEN
    RAISE EXCEPTION 'Unexpected View Once metadata for TTL-only message';
  END IF;
END
$check$;
\echo 'PASS: TTL-only send records server expiry.'

-- Negative cases: no protection mode, disallowed TTL, group View Once,
-- unauthenticated call, outsider, broken envelope coverage, revoked sender.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $check$
DECLARE blocked boolean;
BEGIN
 blocked:=false;
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',
 public.test_envelopes(),NULL,false);
 EXCEPTION WHEN invalid_parameter_value THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Unprotected mode was accepted'; END IF;

 blocked:=false;
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',
 public.test_envelopes(),-1,false);
 EXCEPTION WHEN invalid_parameter_value THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Negative TTL was accepted'; END IF;

 blocked:=false;
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',
 public.test_envelopes(),NULL,true);
 EXCEPTION WHEN invalid_parameter_value THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Group View Once was accepted'; END IF;

 blocked:=false;
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',
 '[]'::jsonb,NULL,true);
 EXCEPTION WHEN others THEN
   IF SQLERRM LIKE '%coverage mismatch%' THEN blocked:=true; ELSE RAISE; END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Missing device envelopes accepted'; END IF;

 blocked:=false;
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',
 pg_catalog.jsonb_build_array(public.test_envelopes()->0,public.test_envelopes()->0),NULL,true);
 EXCEPTION WHEN others THEN
   IF SQLERRM LIKE '%Duplicate recipient device%' THEN blocked:=true; ELSE RAISE; END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Duplicate recipient device accepted'; END IF;
END
$check$;
RESET ROLE;
\echo 'PASS: Mode, TTL, group, missing/duplicate device guards.'

SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $check$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',public.test_envelopes(),30,false);
 EXCEPTION WHEN others THEN
  IF SQLERRM LIKE '%Not a conversation member%' THEN blocked:=true; ELSE RAISE; END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Outsider sent a protected message'; END IF;
END
$check$;
RESET ROLE;
\echo 'PASS: Outsider denied by real official TEST sender RPC.'

SET ROLE authenticated;
RESET request.jwt.claim.sub;
DO $check$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff3','ct','iv',public.test_envelopes(),30,false);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Anonymous auth context was accepted'; END IF;
END
$check$;
RESET ROLE;
\echo 'PASS: No auth.uid() rejected.'

-- Real transaction rollback if metadata INSERT fails after sender insert.
CREATE FUNCTION public.test_metadata_failure() RETURNS trigger LANGUAGE plpgsql
AS $test$ BEGIN RAISE EXCEPTION 'FORCED_METADATA_FAILURE'; END $test$;
CREATE TRIGGER test_fail_viewonce BEFORE INSERT ON public.view_once_messages
FOR EACH ROW EXECUTE FUNCTION public.test_metadata_failure();

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $check$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
 PERFORM public.send_protected_encrypted_message_v2(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'ffffffff-ffff-4fff-8fff-fffffffffff4','ct','iv',public.test_envelopes(),NULL,true);
 EXCEPTION WHEN others THEN
 IF SQLERRM LIKE '%FORCED_METADATA_FAILURE%' THEN blocked:=true; ELSE RAISE; END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Post-send metadata failure did not abort'; END IF;
END
$check$;
RESET ROLE;
DO $check$
BEGIN
 IF EXISTS (SELECT 1 FROM public.messages WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff4') THEN
  RAISE EXCEPTION 'Partial message persisted after metadata failure';
 END IF;
 IF EXISTS (SELECT 1 FROM public.message_envelopes e JOIN public.messages m
 ON m.id=e.message_id WHERE m.client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff4') THEN
  RAISE EXCEPTION 'Orphan envelope persisted after metadata failure';
 END IF;
 IF (SELECT count(*) FROM public.messages)<>2 OR
    (SELECT count(*) FROM public.view_once_messages)<>1 OR
    (SELECT count(*) FROM public.disappearing_messages)<>1 THEN
  RAISE EXCEPTION 'Failed attempt left unexpected rows';
 END IF;
END
$check$;
\echo 'PASS: Forced post-send metadata failure rolls back message and envelopes.'

-- EXPECTED RELEASE BLOCKER: the actual current TEST history RPC returns
-- wrapped keys for View Once without consume/claim, repeatedly. It also
-- returns expired disappearing messages until a separate purge occurs.
-- This assertion PASSES only when the gap is observed in this fixture;
-- therefore an isolated send function PASS is NEVER a shipping green light.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $gap$
DECLARE a text; b text;
BEGIN
 SELECT r.wrapped_key INTO a
 FROM public.get_my_encrypted_messages_v2_for_conversation(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd',50,NULL,NULL
 ) r WHERE r.client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff1';
 SELECT r.wrapped_key INTO b
 FROM public.get_my_encrypted_messages_v2_for_conversation(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd',50,NULL,NULL
 ) r WHERE r.client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff1';
 IF a IS NULL OR b IS NULL OR a <> b THEN
  RAISE EXCEPTION 'Unexpected: current history RPC did not expose repeated View Once envelope';
 END IF;
END
$gap$;
RESET ROLE;
\echo 'EXPECTED RELEASE HOLD: View Once wrapped key is retrievable repeatedly without consume.'

-- Simulate expiry; no actual production data is touched.
UPDATE public.disappearing_messages
SET expires_at=pg_catalog.clock_timestamp()-interval '1 second'
WHERE message_id=(SELECT id FROM public.messages
 WHERE client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff2');
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $gap$
DECLARE keyfound text;
BEGIN
 SELECT r.wrapped_key INTO keyfound
 FROM public.get_my_encrypted_messages_v2_for_conversation(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd',50,NULL,NULL
 ) r WHERE r.client_message_id='ffffffff-ffff-4fff-8fff-fffffffffff2';
 IF keyfound IS NULL THEN
  RAISE EXCEPTION 'Unexpected: current history RPC did not expose expired TTL envelope';
 END IF;
END
$gap$;
RESET ROLE;
\echo 'EXPECTED RELEASE HOLD: expired TTL wrapped key remains readable pending purge/read gate.'

-- Explicitly remove sandbox temporary execute grant to restore release state.
REVOKE EXECUTE ON FUNCTION public.send_protected_encrypted_message_v2(
  uuid,uuid,uuid,text,text,jsonb,integer,boolean
) FROM authenticated;
DO $check$
BEGIN
  IF has_function_privilege('authenticated',
    'public.send_protected_encrypted_message_v2(uuid,uuid,uuid,text,text,jsonb,integer,boolean)', 'EXECUTE')
  THEN RAISE EXCEPTION 'Release guard failed: RPC callable'; END IF;
END
$check$;
\echo 'PASS: Final RPC EXECUTE remains DENIED.'
