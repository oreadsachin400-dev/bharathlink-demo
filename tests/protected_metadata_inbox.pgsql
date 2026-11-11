\set ON_ERROR_STOP on
\echo 'PROTECTED METADATA INBOX LAB — synthetic users/messages, disposable PG16 only'

-- Sender's key-free reader index must persist after View Once consumed and
-- its encrypted vault entries erased in the previous integration test.
DO $check$
DECLARE
  once_id uuid;
  group_id uuid;
BEGIN
  SELECT id INTO once_id FROM public.messages
    WHERE client_message_id='e0000000-0000-4000-8000-000000000001';
  SELECT id INTO group_id FROM public.messages
    WHERE client_message_id='e0000000-0000-4000-8000-000000000002';
  IF (SELECT count(*) FROM bl_protected_lab.authorized_readers
      WHERE message_id=once_id)<>2 THEN
    RAISE EXCEPTION 'View Once original readers not retained after claim';
  END IF;
  IF (SELECT count(*) FROM bl_protected_lab.authorized_readers
      WHERE message_id=group_id)<>3 THEN
    RAISE EXCEPTION 'Group TTL original reader index incomplete';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.message_envelopes e
    WHERE e.message_id IN (once_id,group_id)
  ) THEN RAISE EXCEPTION 'Metadata test detected public wrapped key'; END IF;
END $check$;
\echo 'PASS: Immutable reader index survives consume and never creates public envelopes.'

SET ROLE anon;
DO $deny$
DECLARE denied boolean:=false;
BEGIN
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Anonymous can query protected inbox'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $deny$
DECLARE denied boolean:=false;
BEGIN
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Protected inbox callable without release'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: New inbox RPC defaults to anon/authenticated EXECUTE denied.'

-- Isolated test-only permissions. No changes to actual app role or grants.
GRANT EXECUTE ON FUNCTION public.list_my_protected_messages_v1(
  uuid,uuid,integer,timestamptz,uuid
) TO authenticated;

SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE
  item record;
  dump jsonb;
BEGIN
  SELECT * INTO item FROM public.list_my_protected_messages_v1(
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,NULL);
  IF NOT FOUND OR item.is_view_once IS DISTINCT FROM true
     OR item.availability<>'consumed'
     OR item.message_ciphertext IS NOT NULL OR item.message_iv IS NOT NULL
  THEN RAISE EXCEPTION 'Consumed View Once body should be a keyless tombstone'; END IF;

  SELECT pg_catalog.to_jsonb(i) INTO dump
  FROM public.list_my_protected_messages_v1(
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,NULL
  ) i LIMIT 1;
  IF dump ?| ARRAY['wrappedKey','wrapped_key','wrap_iv','ephPub',
                   'eph_pub','recipient_device_id','sender_public_key_jwk']
     OR dump::text LIKE '%recipient-first-key%'
  THEN RAISE EXCEPTION 'Inbox exposes any wrapped key or key-material column'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Consumed View Once is visible only as tombstone, no encrypted body or key.'

-- Group member C (verified signer) was an original recipient.
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $check$
DECLARE rowdata record;
BEGIN
  SELECT * INTO rowdata FROM public.list_my_protected_messages_v1(
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc',20,NULL,NULL);
  IF NOT FOUND OR rowdata.availability<>'available'
     OR rowdata.is_view_once IS DISTINCT FROM false
     OR rowdata.message_ciphertext<>'group-ct'
     OR rowdata.message_iv<>'iv'
  THEN RAISE EXCEPTION 'Original group recipient missing encrypted payload'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Original verified group recipient can list encrypted payload without any key.'

-- Original sender also has signer-approved original recipient indexing.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $check$
DECLARE total integer;
BEGIN
  SELECT count(*) INTO total FROM public.list_my_protected_messages_v1(
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',20,NULL,NULL);
  IF total<>1 THEN RAISE EXCEPTION 'Original sender view missing consumed entry'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Original sender sees protected item state without recipient keys.'

-- Authorised original recipient but revoked/unsigned device cannot list.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE denied boolean:=false;
BEGIN
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd',20,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Revoked B device read protected metadata'; END IF;
  denied:=false;
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe',20,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Unsigned B device read protected metadata'; END IF;
  denied:=false;
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',0,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Zero limit accepted'; END IF;
  denied:=false;
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',51,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Unbounded limit accepted'; END IF;
  denied:=false;
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,
      'e0000000-0000-4000-8000-000000000001');
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Invalid pagination cursor accepted'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Revoked/unsigned devices and invalid pagination fail closed.'

-- Outsider with valid signed device cannot enumerate a private conversation.
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $check$
DECLARE denied boolean:=false;
BEGIN
  BEGIN
    PERFORM public.list_my_protected_messages_v1(
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc',20,NULL,NULL);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'Outsider read direct metadata'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Non-member cannot enumerate direct protected messages.'

-- Future group member D joins after the TTL message was sent. Even with an
-- independently verified device, they did NOT receive an original key and
-- must not see older protected metadata.
INSERT INTO public.conversation_members(conversation_id,user_id)
VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        '44444444-4444-4444-8444-444444444444');
INSERT INTO public.messaging_devices(id,user_id,public_key_jwk)
VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddc',
        '44444444-4444-4444-8444-444444444444','{"kty":"EC"}');
INSERT INTO public.messaging_device_signing_keys(
  device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddc',
        '44444444-4444-4444-8444-444444444444',
        '{"kty":"EC"}',pg_catalog.clock_timestamp(),'trusted_device_signature');
SET ROLE authenticated;
SET request.jwt.claim.sub='44444444-4444-4444-8444-444444444444';
DO $check$
DECLARE total integer;
BEGIN
  SELECT count(*) INTO total FROM public.list_my_protected_messages_v1(
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'dddddddd-dddd-4ddd-8ddd-dddddddddddc',20,NULL,NULL);
  IF total<>0 THEN RAISE EXCEPTION 'New group member saw prior protected message'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Newly joining group member cannot enumerate previous protected messages.'

-- Mark the original synthetic group TTL expired while cleanup is delayed.
UPDATE public.disappearing_messages
SET expires_at=pg_catalog.clock_timestamp()-interval '1 second'
WHERE message_id=(SELECT id FROM public.messages
  WHERE client_message_id='e0000000-0000-4000-8000-000000000002');
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $check$
DECLARE entry record;
BEGIN
  SELECT * INTO entry FROM public.list_my_protected_messages_v1(
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc',20,NULL,NULL);
  IF entry.availability<>'expired'
     OR entry.message_ciphertext IS NOT NULL OR entry.message_iv IS NOT NULL
  THEN RAISE EXCEPTION 'Expired protected message body leaked'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Expired TTL is tombstone even when actual purge has not run.'

-- Cleanup may erase vault keys but must not erase key-free original recipient
-- metadata/index (for safe expired UI state).
SELECT bl_protected_lab.purge_expired_wrapped_keys(500) AS purged_count;
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE entry record;
BEGIN
  SELECT * INTO entry FROM public.list_my_protected_messages_v1(
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',20,NULL,NULL);
  IF NOT FOUND OR entry.availability<>'expired'
     OR entry.message_ciphertext IS NOT NULL
  THEN RAISE EXCEPTION 'Expiry tombstone disappeared after purge'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Expired tombstone remains after private key erasure.'

-- No production client grants are left behind after isolated tests.
REVOKE EXECUTE ON FUNCTION public.list_my_protected_messages_v1(
 uuid,uuid,integer,timestamptz,uuid) FROM authenticated;
DO $check$
BEGIN
  IF has_function_privilege('authenticated',
    'public.list_my_protected_messages_v1(uuid,uuid,integer,timestamptz,uuid)',
    'EXECUTE') THEN RAISE EXCEPTION 'Inbox function accidentally released'; END IF;
END $check$;
\echo 'PASS: Protected inbox EXECUTE denied at test end.'
