\set ON_ERROR_STOP on
\echo 'PROTECTED CLAIM ROLLBACK LAB — synthetic data only'

INSERT INTO public.messages(id,conversation_id,sender_id,sender_device_id,
  client_message_id,ciphertext,iv,encryption_version)
VALUES ('f0000000-0000-4000-8000-000000000010',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'f0000000-0000-4000-8000-000000000010','ct','iv',2);
INSERT INTO public.view_once_messages
 (message_id,conversation_id,sender_id,recipient_user_id)
VALUES ('f0000000-0000-4000-8000-000000000010',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',
 '22222222-2222-4222-8222-222222222222');
INSERT INTO bl_protected_lab.wrapped_keys
 (message_id,recipient_user_id,recipient_device_id,wrapped_key,wrap_iv,eph_pub)
VALUES
 ('f0000000-0000-4000-8000-000000000010',
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 'rollback-device-1','iv','{"kty":"EC"}'),
 ('f0000000-0000-4000-8000-000000000010',
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc',
 'rollback-device-2','iv','{"kty":"EC"}');

CREATE FUNCTION bl_protected_lab.inject_delete_failure()
RETURNS trigger LANGUAGE plpgsql AS $trigger$
BEGIN
  IF OLD.message_id='f0000000-0000-4000-8000-000000000010'
  THEN RAISE EXCEPTION 'FORCED_VAULT_DELETE_FAILURE'; END IF;
  RETURN OLD;
END $trigger$;
CREATE TRIGGER inject_vault_delete_failure
BEFORE DELETE ON bl_protected_lab.wrapped_keys
FOR EACH ROW EXECUTE FUNCTION bl_protected_lab.inject_delete_failure();

GRANT EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid) TO authenticated;
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000010',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN others THEN
  IF SQLERRM LIKE '%FORCED_VAULT_DELETE_FAILURE%' THEN
   blocked:=true;
  ELSE RAISE;
  END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Forced vault delete failure did not abort claim'; END IF;
END $check$;
RESET ROLE;

DO $check$
BEGIN
 IF (SELECT consumed_at FROM public.view_once_messages
  WHERE message_id='f0000000-0000-4000-8000-000000000010') IS NOT NULL
 THEN RAISE EXCEPTION 'Failed claim consumed View Once message'; END IF;
 IF (SELECT count(*) FROM bl_protected_lab.wrapped_keys
  WHERE message_id='f0000000-0000-4000-8000-000000000010')<>2
 THEN RAISE EXCEPTION 'Failed claim partially erased key vault'; END IF;
END $check$;
\echo 'PASS: Vault deletion failure rolls back consumption; no keys lost.'

DROP TRIGGER inject_vault_delete_failure ON bl_protected_lab.wrapped_keys;
DROP FUNCTION bl_protected_lab.inject_delete_failure();

SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE result jsonb;
BEGIN
 result:=public.claim_protected_wrapped_key_v1(
  'f0000000-0000-4000-8000-000000000010',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 IF result->>'wrappedKey'<>'rollback-device-1' THEN
  RAISE EXCEPTION 'Claim retry after rollback failed'; END IF;
END $check$;
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT consumed_at FROM public.view_once_messages
  WHERE message_id='f0000000-0000-4000-8000-000000000010') IS NULL
 THEN RAISE EXCEPTION 'Claim retry not consumed'; END IF;
 IF EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
  WHERE message_id='f0000000-0000-4000-8000-000000000010')
 THEN RAISE EXCEPTION 'Claim retry did not erase all key copies'; END IF;
END $check$;
REVOKE EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 FROM authenticated;
\echo 'PASS: After rollback, safe retry consumes once and erases all envelopes.'
