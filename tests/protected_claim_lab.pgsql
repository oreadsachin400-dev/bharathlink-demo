\set ON_ERROR_STOP on
\echo 'CLAIM-LAB: disposable PG16, no live accounts/data'

-- The preceding sender regression forced a trigger error to check rollback.
-- Remove it in THIS synthetic database before creating protected metadata.
DROP TRIGGER IF EXISTS test_fail_viewonce ON public.view_once_messages;
DROP FUNCTION IF EXISTS public.test_metadata_failure();

-- A second local device for the same recipient tests cross-device races.
INSERT INTO public.messaging_devices(id,user_id,public_key_jwk) VALUES
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc',
 '22222222-2222-4222-8222-222222222222','{"kty":"EC"}'),
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd',
 '22222222-2222-4222-8222-222222222222','{"kty":"EC"}'),
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe',
 '22222222-2222-4222-8222-222222222222','{"kty":"EC"}');
UPDATE public.messaging_devices
SET revoked_at=pg_catalog.clock_timestamp()
WHERE id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd';

INSERT INTO public.messaging_device_signing_keys
 (device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
VALUES
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 '22222222-2222-4222-8222-222222222222',
 '{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}',pg_catalog.clock_timestamp(),'trusted_device_signature'),
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc',
 '22222222-2222-4222-8222-222222222222',
 '{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}',pg_catalog.clock_timestamp(),'trusted_device_signature'),
('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd',
 '22222222-2222-4222-8222-222222222222',
 '{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}',pg_catalog.clock_timestamp(),'trusted_device_signature'),
('cccccccc-cccc-4ccc-8ccc-cccccccccccc',
 '33333333-3333-4333-8333-333333333333',
 '{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}',pg_catalog.clock_timestamp(),'trusted_device_signature');

-- Protected messages have PUBLIC ciphertext metadata, but NO wrapped keys in
-- public.message_envelopes. Only private vault receives wrapped keys.
INSERT INTO public.messages(id,conversation_id,sender_id,sender_device_id,
  client_message_id,ciphertext,iv,encryption_version)
SELECT x.id,'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 x.id,'protected-encrypted-ct','protected-iv',2
FROM (VALUES
 ('f0000000-0000-4000-8000-000000000001'::uuid),
 ('f0000000-0000-4000-8000-000000000002'::uuid),
 ('f0000000-0000-4000-8000-000000000003'::uuid),
 ('f0000000-0000-4000-8000-000000000004'::uuid),
 ('f0000000-0000-4000-8000-000000000005'::uuid),
 ('f0000000-0000-4000-8000-000000000006'::uuid),
 ('f0000000-0000-4000-8000-000000000007'::uuid),
 ('f0000000-0000-4000-8000-000000000008'::uuid)
) x(id);
INSERT INTO public.view_once_messages
 (message_id,conversation_id,sender_id,recipient_user_id)
SELECT x.id,'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',
 '22222222-2222-4222-8222-222222222222'
FROM (VALUES ('f0000000-0000-4000-8000-000000000001'::uuid),
 ('f0000000-0000-4000-8000-000000000006'::uuid)) x(id);
INSERT INTO public.disappearing_messages
 (message_id,conversation_id,sender_id,ttl_sec,expires_at)
SELECT x.id,'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',3600,
 pg_catalog.clock_timestamp() + interval '1 hour'
FROM (VALUES
 ('f0000000-0000-4000-8000-000000000002'::uuid),
 ('f0000000-0000-4000-8000-000000000003'::uuid),
 ('f0000000-0000-4000-8000-000000000004'::uuid),
 ('f0000000-0000-4000-8000-000000000005'::uuid),
 ('f0000000-0000-4000-8000-000000000007'::uuid),
 ('f0000000-0000-4000-8000-000000000008'::uuid)
) x(id);
UPDATE public.disappearing_messages
 SET expires_at=pg_catalog.clock_timestamp() - interval '1 second'
 WHERE message_id='f0000000-0000-4000-8000-000000000003';

-- Two envelopes for the same View Once recipient across two devices.
INSERT INTO bl_protected_lab.wrapped_keys
 (message_id,recipient_user_id,recipient_device_id,wrapped_key,wrap_iv,eph_pub)
SELECT x.msg,'22222222-2222-4222-8222-222222222222',
 x.dev,x.key,'wrapped-iv','{"kty":"EC"}'
FROM (VALUES
 ('f0000000-0000-4000-8000-000000000001'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'once-device-1'),
 ('f0000000-0000-4000-8000-000000000001'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc'::uuid,'once-device-2'),
 ('f0000000-0000-4000-8000-000000000002'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'ttl-active'),
 ('f0000000-0000-4000-8000-000000000003'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'ttl-expired'),
 ('f0000000-0000-4000-8000-000000000004'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe'::uuid,'ttl-unsigned'),
 ('f0000000-0000-4000-8000-000000000005'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd'::uuid,'ttl-revoked'),
 ('f0000000-0000-4000-8000-000000000006'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'race-device-1'),
 ('f0000000-0000-4000-8000-000000000006'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc'::uuid,'race-device-2'),
 ('f0000000-0000-4000-8000-000000000008'::uuid,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'ttl-deleted')
) x(msg,dev,key);
-- Deliberate forged recipient envelope must not defeat membership check.
INSERT INTO bl_protected_lab.wrapped_keys
 (message_id,recipient_user_id,recipient_device_id,wrapped_key,wrap_iv,eph_pub)
VALUES ('f0000000-0000-4000-8000-000000000007',
 '33333333-3333-4333-8333-333333333333',
 'cccccccc-cccc-4ccc-8ccc-cccccccccccc','ttl-outsider','wrapped-iv','{"kty":"EC"}');

UPDATE public.messages SET deleted_at=pg_catalog.clock_timestamp()
 WHERE id='f0000000-0000-4000-8000-000000000008';

-- Verify the deliberate lack of existing history envelopes before claim.
DO $check$
BEGIN
 IF EXISTS (
   SELECT 1 FROM public.message_envelopes e
   WHERE e.message_id::text LIKE 'f0000000-0000-4000-8000-%'
 ) THEN RAISE EXCEPTION 'Protected wrapped key leaked into normal history'; END IF;
END $check$;
\echo 'PASS: Vault-only envelopes; zero matching normal message_envelopes.'

-- Direct data access and public claim EXECUTE both denied by default.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM * FROM bl_protected_lab.wrapped_keys;
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Vault exposed to authenticated role'; END IF;
 denied:=false;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000001',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Protected claim callable before approval'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Private key vault inaccessible and claim RPC default DENY.'

-- Sandbox-only grant. Never replicate in the actual Supabase project.
GRANT EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 TO authenticated;

-- Current official TEST history RPC must NOT expose lab-only protected keys,
-- because the private keys were never placed in message_envelopes.
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n
 FROM public.get_my_encrypted_messages_v2_for_conversation(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd',50,NULL,NULL
 ) h WHERE h.message_id='f0000000-0000-4000-8000-000000000001';
 IF n<>0 THEN RAISE EXCEPTION 'Normal history exposed a protected key'; END IF;
END $check$;

-- First claim wins, key material E2EE-wrapped for this local device.
DO $claim$
DECLARE result jsonb; denied boolean:=false;
BEGIN
 result:=public.claim_protected_wrapped_key_v1(
  'f0000000-0000-4000-8000-000000000001',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 IF result->>'wrappedKey' <> 'once-device-1'
    OR result->>'viewOnce'<>'true' THEN
  RAISE EXCEPTION 'First View Once claim returned wrong envelope';
 END IF;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000001',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Same-device replay returned key'; END IF;
END $claim$;
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT consumed_device_id FROM public.view_once_messages
   WHERE message_id='f0000000-0000-4000-8000-000000000001')
    <> 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid THEN
   RAISE EXCEPTION 'View Once claimant device not recorded';
 END IF;
 IF EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
   WHERE message_id='f0000000-0000-4000-8000-000000000001') THEN
   RAISE EXCEPTION 'Alternate device envelopes not deleted';
 END IF;
END $check$;
\echo 'PASS: View Once first claim, replay denied, all device envelopes erased.'

SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $negative$
DECLARE denied boolean:=false; result jsonb;
BEGIN
 -- The other device loses after the first winner has consumed.
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000001',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Cross-device replay succeeded'; END IF;
 
 -- TTL is re-readable before expiry (unlike View Once).
 result:=public.claim_protected_wrapped_key_v1(
  'f0000000-0000-4000-8000-000000000002',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 IF result->>'wrappedKey'<>'ttl-active' OR result->>'viewOnce'<>'false' THEN
  RAISE EXCEPTION 'Active TTL key denied incorrectly';
 END IF;
 result:=public.claim_protected_wrapped_key_v1(
  'f0000000-0000-4000-8000-000000000002',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 IF result->>'wrappedKey'<>'ttl-active' THEN
  RAISE EXCEPTION 'Active TTL retry rejected';
 END IF;
 denied:=false;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000003',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Expired TTL key was served'; END IF;

 denied:=false;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000004',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbe');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Unsigned device was accepted'; END IF;

 denied:=false;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000005',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbd');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Revoked device was accepted'; END IF;

 denied:=false;
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000008',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Deleted message key served'; END IF;
END $negative$;
RESET ROLE;
\echo 'PASS: Cross-device replay/expiry/unsigned/revoked/deleted denied.'

SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $negative$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000007',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Outsider with forged vault row got key'; END IF;
END $negative$;
RESET ROLE;

SET ROLE authenticated;
RESET request.jwt.claim.sub;
DO $negative$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000002',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Missing auth.uid got key'; END IF;
END $negative$;
RESET ROLE;
\echo 'PASS: Forged outsider envelope and missing auth denied.'

-- Restore default-denied function even after isolated tests.
REVOKE EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 FROM authenticated;
DO $check$
BEGIN
 IF has_function_privilege('authenticated',
  'public.claim_protected_wrapped_key_v1(uuid,uuid)','EXECUTE') THEN
  RAISE EXCEPTION 'Claim RPC left callable after isolated test';
 END IF;
END $check$;
\echo 'PASS: Claim RPC final EXECUTE denied.'

-- The synthetic race test only runs after TEST-ONLY temporary grant, in
-- separate script with external session synchronization.
