\set ON_ERROR_STOP on
\echo 'VAULT-ONLY SENDER LAB — disposable PostgreSQL 16 only'

CREATE FUNCTION public.test_vault_env(
 p_user uuid,p_device uuid,p_key text
) RETURNS jsonb LANGUAGE sql IMMUTABLE
AS $test$
SELECT pg_catalog.jsonb_build_object(
 'recipient_user_id',p_user::text,
 'recipient_device_id',p_device::text,
 'ciphertext',p_key,'iv','wrapped-iv',
 'eph_pub',pg_catalog.jsonb_build_object('kty','EC'),
 'encryption_version',2
)
$test$;

CREATE FUNCTION public.test_vault_env_direct() RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $test$
SELECT pg_catalog.jsonb_build_array(
 public.test_vault_env('11111111-1111-4111-8111-111111111111',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','sender-wrapped-key'),
 public.test_vault_env('22222222-2222-4222-8222-222222222222',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','recipient-first-key'),
 public.test_vault_env('22222222-2222-4222-8222-222222222222',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc','recipient-second-key')
)
$test$;
CREATE FUNCTION public.test_vault_env_group() RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $test$
SELECT public.test_vault_env_direct()||
 pg_catalog.jsonb_build_array(
 public.test_vault_env('33333333-3333-4333-8333-333333333333',
 'cccccccc-cccc-4ccc-8ccc-cccccccccccc','group-member-key'))
$test$;

-- Enforce active and independently trusted signing device for sender too.
INSERT INTO public.messaging_device_signing_keys(
 device_id,user_id,signing_public_key_jwk,verified_at,verification_method
) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 '11111111-1111-4111-8111-111111111111',
 '{"kty":"EC"}',pg_catalog.clock_timestamp(),'trusted_device_signature');

-- Deploy candidate in this disposable DB with client EXECUTE denied.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000001',
   'ct','iv',public.test_vault_env_direct(),NULL,true);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Vault sender has default client EXECUTE'; END IF;
END $deny$;
RESET ROLE;
SET ROLE anon;
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000001',
   'ct','iv',public.test_vault_env_direct(),NULL,true);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Anonymous can use vault sender'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Vault-only sender remains denied to authenticated and anon.'

-- Test-only temporary grant. NEVER add this GRANT to production review SQL.
GRANT EXECUTE ON FUNCTION public.send_protected_vault_message_v1(
 uuid,uuid,uuid,text,text,jsonb,integer,boolean) TO authenticated;

-- Active but unsigned recipient bbe must fail closed, even with full device
-- coverage count; the server must not silently omit its keys.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $test$
DECLARE denied boolean:=false; all_envelopes jsonb;
BEGIN
 all_envelopes:=public.test_vault_env_direct()||
  pg_catalog.jsonb_build_array(
    public.test_vault_env('22222222-2222-4222-8222-222222222222',
     'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe','untrusted-recipient-key'));
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000001',
   'ct','iv',all_envelopes,NULL,true);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Unverified recipient device accepted'; END IF;
END $test$;
RESET ROLE;
DO $test$
BEGIN
 IF EXISTS(SELECT 1 FROM public.messages
 WHERE client_message_id='e0000000-0000-4000-8000-000000000001') THEN
  RAISE EXCEPTION 'Failed trust validation wrote a public message';
 END IF;
END $test$;
\echo 'PASS: Active recipient without verified signer prevents protected send.'

-- Synthetic fixture only: revoke untrusted device, preserving real TEST.
UPDATE public.messaging_devices SET revoked_at=pg_catalog.clock_timestamp()
 WHERE id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe';

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.send_protected_vault_message_v1(
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'e0000000-0000-4000-8000-000000000001',
 'protected-vault-ct','msg-iv',public.test_vault_env_direct(),NULL,true)
 AS protected_message_id;
RESET ROLE;

DO $check$
DECLARE mid uuid;
BEGIN
 SELECT id INTO mid FROM public.messages
 WHERE client_message_id='e0000000-0000-4000-8000-000000000001';
 IF mid IS NULL OR (SELECT count(*) FROM public.view_once_messages
 WHERE message_id=mid AND
 recipient_user_id='22222222-2222-4222-8222-222222222222')<>1 THEN
  RAISE EXCEPTION 'View Once metadata missing for vault send';
 END IF;
 IF EXISTS(SELECT 1 FROM public.message_envelopes WHERE message_id=mid) THEN
  RAISE EXCEPTION 'PROTECTED DECRYPTION KEY LEAKED TO NORMAL HISTORY';
 END IF;
 IF (SELECT count(*) FROM bl_protected_lab.wrapped_keys WHERE message_id=mid)<>3 THEN
  RAISE EXCEPTION 'Expected all three active device keys in vault';
 END IF;
END $check$;
\echo 'PASS: View Once sender writes three private keys, zero normal envelopes.'

-- Current official TEST history RPC must return zero keys for protected send.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n FROM
 public.get_my_encrypted_messages_v2_for_conversation(
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',50,NULL,NULL) h
 WHERE h.client_message_id='e0000000-0000-4000-8000-000000000001';
 IF n<>0 THEN RAISE EXCEPTION 'Normal history exposes protected key'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Exact TEST history function cannot retrieve vault-only decryption key.'

-- Use the server-returned message ID from the privileged disposable test
-- setup, not a direct SELECT by the client. Production RLS remains untouched.
SELECT pg_catalog.set_config('bhl.test_claim_message_id',id::text,false)
FROM public.messages
WHERE client_message_id='e0000000-0000-4000-8000-000000000001';

-- A true end-to-end send -> read-once -> cleanup path.
GRANT EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 TO authenticated;
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $claim$
DECLARE mid uuid := pg_catalog.current_setting('bhl.test_claim_message_id')::uuid;
 envelope jsonb; denied boolean:=false;
BEGIN
 envelope:=public.claim_protected_wrapped_key_v1(
 mid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 IF envelope->>'wrappedKey'<>'recipient-first-key'
 OR envelope->>'viewOnce'<>'true' THEN
  RAISE EXCEPTION 'Recipient claim returned wrong E2EE envelope';
 END IF;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   mid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Second signed device received already-consumed key'; END IF;
END $claim$;
RESET ROLE;
REVOKE EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 FROM authenticated;
DO $check$
DECLARE mid uuid;
BEGIN
 SELECT id INTO mid FROM public.messages
 WHERE client_message_id='e0000000-0000-4000-8000-000000000001';
 IF (SELECT consumed_at FROM public.view_once_messages WHERE message_id=mid) IS NULL
 OR EXISTS(SELECT 1 FROM bl_protected_lab.wrapped_keys WHERE message_id=mid) THEN
  RAISE EXCEPTION 'Claim did not atomically consume and erase all device copies';
 END IF;
END $check$;
\echo 'PASS: Send -> claim -> replay denied -> all recipient/sender wrapped keys erased.'

-- TTL-only group message uses all active group devices (including member C).
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
SELECT public.send_protected_vault_message_v1(
 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'e0000000-0000-4000-8000-000000000002',
 'group-ct','iv',public.test_vault_env_group(),30,false) AS ttl_message_id;
RESET ROLE;
DO $check$
DECLARE mid uuid;
BEGIN
 SELECT id INTO mid FROM public.messages
 WHERE client_message_id='e0000000-0000-4000-8000-000000000002';
 IF (SELECT count(*) FROM public.disappearing_messages
  WHERE message_id=mid AND ttl_sec=30
    AND expires_at>pg_catalog.clock_timestamp())<>1
 OR (SELECT count(*) FROM bl_protected_lab.wrapped_keys
  WHERE message_id=mid)<>4
 OR EXISTS(SELECT 1 FROM public.message_envelopes WHERE message_id=mid) THEN
   RAISE EXCEPTION 'Group TTL send mismatch: metadata, coverage or leak';
 END IF;
END $check$;
\echo 'PASS: Group disappearing message covers all four verified active devices.'

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $bad$
DECLARE rejected boolean;
BEGIN
 -- Do not permit View Once group using single-recipient metadata.
 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',public.test_vault_env_group(),NULL,true);
 EXCEPTION WHEN invalid_parameter_value THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Group view once accepted'; END IF;

 -- All active chat devices required; reject missing envelope.
 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv','[]'::jsonb,NULL,true);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Missing device keys accepted'; END IF;

 -- Duplicate same device with correct array length.
 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',pg_catalog.jsonb_build_array(
      public.test_vault_env_direct()->0,
      public.test_vault_env_direct()->1,
      public.test_vault_env_direct()->1),NULL,true);
 EXCEPTION WHEN invalid_parameter_value THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Duplicate device key accepted'; END IF;

 -- Plaintext-like malformed wrapper without ECDH ephemeral JWK rejected.
 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',pg_catalog.jsonb_set(public.test_vault_env_direct(),
        '{1,eph_pub}', 'null'::jsonb),NULL,true);
 EXCEPTION WHEN invalid_parameter_value THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Malformed ECDH wrapper accepted'; END IF;

 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',public.test_vault_env_direct(),-1,false);
 EXCEPTION WHEN invalid_parameter_value THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Invalid TTL accepted'; END IF;

 rejected:=false;
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',public.test_vault_env_direct(),NULL,false);
 EXCEPTION WHEN invalid_parameter_value THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'No protection mode accepted'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Reject group View Once, missing/duplicate keys, bad ECDH wrapper and TTL.'

-- An outsider with a verified signing key still cannot send to direct chat.
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $bad$
DECLARE rejected boolean:=false;
BEGIN
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'e0000000-0000-4000-8000-000000000003',
   'ct','iv',public.test_vault_env_direct(),30,false);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Outsider sent protected message'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Outsider cannot send even with independently verified signer.'

-- Duplicate sender/client IDs are uniquely constrained, do not create copies.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $bad$
DECLARE rejected boolean:=false;
BEGIN
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000001',
   'ct','iv',public.test_vault_env_direct(),NULL,true);
 EXCEPTION WHEN unique_violation THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Duplicate protected client ID was inserted'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Official TEST client-message uniqueness blocks duplicate sends.'

-- Force vault INSERT failure AFTER message & View Once metadata were written.
CREATE FUNCTION bl_protected_lab.inject_sender_vault_error()
 RETURNS trigger LANGUAGE plpgsql AS $trigger$
BEGIN
 IF NEW.wrapped_key='force-insert-fail' THEN
   RAISE EXCEPTION 'FORCED_VAULT_INSERT_ERROR';
 END IF;
 RETURN NEW;
END $trigger$;
CREATE TRIGGER test_vault_sender_insert_fail
 BEFORE INSERT ON bl_protected_lab.wrapped_keys
 FOR EACH ROW EXECUTE FUNCTION bl_protected_lab.inject_sender_vault_error();

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $bad$
DECLARE rejected boolean:=false;
BEGIN
 BEGIN
  PERFORM public.send_protected_vault_message_v1(
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'e0000000-0000-4000-8000-000000000004',
   'ct','iv',
   pg_catalog.jsonb_set(public.test_vault_env_direct(),'{1,ciphertext}',
     '"force-insert-fail"'::jsonb),NULL,true);
 EXCEPTION WHEN others THEN
  IF SQLERRM LIKE '%FORCED_VAULT_INSERT_ERROR%' THEN rejected:=true; ELSE RAISE; END IF;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'Failed vault INSERT did not abort send'; END IF;
END $bad$;
RESET ROLE;
DO $check$
BEGIN
 IF EXISTS(SELECT 1 FROM public.messages
  WHERE client_message_id='e0000000-0000-4000-8000-000000000004') THEN
  RAISE EXCEPTION 'Partially inserted protected message persisted'; END IF;
 IF EXISTS(SELECT 1 FROM public.view_once_messages vo
  JOIN public.messages m ON m.id=vo.message_id
  WHERE m.client_message_id='e0000000-0000-4000-8000-000000000004') THEN
  RAISE EXCEPTION 'Partial protected metadata persisted'; END IF;
END $check$;
DROP TRIGGER test_vault_sender_insert_fail ON bl_protected_lab.wrapped_keys;
DROP FUNCTION bl_protected_lab.inject_sender_vault_error();
\echo 'PASS: Forced vault write failure atomically rolls back message and metadata.'

REVOKE EXECUTE ON FUNCTION public.send_protected_vault_message_v1(
 uuid,uuid,uuid,text,text,jsonb,integer,boolean) FROM authenticated;
DO $check$
BEGIN
 IF has_function_privilege('authenticated',
 'public.send_protected_vault_message_v1(uuid,uuid,uuid,text,text,jsonb,integer,boolean)',
 'EXECUTE') THEN
  RAISE EXCEPTION 'Vault sender left callable after disposable tests'; END IF;
END $check$;
\echo 'PASS: Vault sender final authenticated EXECUTE denied.'
