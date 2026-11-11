\set ON_ERROR_STOP on
\echo 'PROTECTED EXPIRY LAB: Synthetic records only; do not run on TEST/PROD'

-- Mixed-storage protection: a public envelope invalidates claim protection.
INSERT INTO public.messages(id,conversation_id,sender_id,sender_device_id,
 client_message_id,ciphertext,iv,encryption_version)
VALUES ('f0000000-0000-4000-8000-000000000009',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'f0000000-0000-4000-8000-000000000009',
 'protected-ct','iv',2);
INSERT INTO public.disappearing_messages
 (message_id,conversation_id,sender_id,ttl_sec,expires_at)
VALUES ('f0000000-0000-4000-8000-000000000009',
 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
 '11111111-1111-4111-8111-111111111111',3600,
 pg_catalog.clock_timestamp()+interval '1 hour');
INSERT INTO bl_protected_lab.wrapped_keys
 (message_id,recipient_user_id,recipient_device_id,wrapped_key,wrap_iv,eph_pub)
VALUES ('f0000000-0000-4000-8000-000000000009',
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 'vault-only-expected','iv','{"kty":"EC"}');
-- Simulates an unsafe old sender that ALSO left a key in public envelope.
INSERT INTO public.message_envelopes(message_id,recipient_user_id,
 recipient_device_id,ciphertext,iv,eph_pub,encryption_version)
VALUES ('f0000000-0000-4000-8000-000000000009',
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 'unsafe-public-key','iv','{"kty":"EC"}',2);

-- Sandbox grant to invoke claim only in this disposable database.
GRANT EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 TO authenticated;
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.claim_protected_wrapped_key_v1(
   'f0000000-0000-4000-8000-000000000009',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Mixed-storage message wrongly claimable'; END IF;
END $check$;
RESET ROLE;
REVOKE EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
 FROM authenticated;
\echo 'PASS: Mixed public+private key storage rejected instead of false View Once guarantee.'

SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $check$
DECLARE denied boolean:=false;
BEGIN
 BEGIN PERFORM bl_protected_lab.purge_expired_wrapped_keys(10);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Client could call private purge'; END IF;
END $check$;
RESET ROLE;
\echo 'PASS: Protected cleanup not callable by app clients.'

-- Expired key is denied by claim at read time even if cleanup is delayed.
-- Now prove trusted server cleanup eventually deletes its vault copy.
DO $test$
DECLARE erased integer;
BEGIN
 IF NOT EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
  WHERE message_id='f0000000-0000-4000-8000-000000000003')
 THEN RAISE EXCEPTION 'Expired test key unexpectedly absent before purge'; END IF;

 erased:=bl_protected_lab.purge_expired_wrapped_keys(500);
 IF erased < 1 THEN RAISE EXCEPTION 'No expired rows purged'; END IF;

 IF EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
  WHERE message_id='f0000000-0000-4000-8000-000000000003')
 THEN RAISE EXCEPTION 'Expired key remained after purge'; END IF;

 IF (SELECT purged_at FROM public.disappearing_messages
  WHERE message_id='f0000000-0000-4000-8000-000000000003') IS NULL
 THEN RAISE EXCEPTION 'Purge marker missing'; END IF;

 IF NOT EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
  WHERE message_id='f0000000-0000-4000-8000-000000000002')
 THEN RAISE EXCEPTION 'Active TTL key accidentally purged'; END IF;
 IF bl_protected_lab.purge_expired_wrapped_keys(500) <> 0
 THEN RAISE EXCEPTION 'Purge not idempotent'; END IF;
END $test$;
\echo 'PASS: Expired vault keys erased; active keys retained; cleanup idempotent.'

DO $test$
BEGIN
 BEGIN
  PERFORM bl_protected_lab.purge_expired_wrapped_keys(0);
  RAISE EXCEPTION 'Invalid cleanup batch accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 BEGIN
  PERFORM bl_protected_lab.purge_expired_wrapped_keys(10000);
  RAISE EXCEPTION 'Unbounded cleanup batch accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
END $test$;
\echo 'PASS: Cleanup rejects invalid/unbounded batch limits.'
