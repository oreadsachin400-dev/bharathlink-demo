-- Phase7I: real disposable PostgreSQL negative gate assertions.
DO $test$
DECLARE
 u1 uuid:='11111111-1111-4111-8111-111111111111';
 u2 uuid:='99999999-9999-4999-8999-999999999999';
 trusted uuid:='22222222-2222-4222-8222-222222222222';
 historic uuid:='abababab-abab-4bab-8bab-abababababab';
 blocked boolean;
 first_id uuid:='12121212-1212-4212-8212-121212121212';
BEGIN
 IF has_schema_privilege('service_role','bl20_first_device_hold_private','USAGE')
 OR has_function_privilege('anon',
  'bl20_first_device_hold_private.guard_device_identity()','EXECUTE')
 OR has_function_privilege('authenticated',
  'bl20_first_device_hold_private.guard_signing_identity()','EXECUTE')
 OR has_function_privilege('service_role',
  'bl20_first_device_hold_private.guard_signing_identity()','EXECUTE')
 THEN RAISE EXCEPTION 'FAIL: private first-device hold API exposed'; END IF;

 IF (SELECT relrowsecurity FROM pg_class
   WHERE oid='public.messaging_device_signing_keys'::regclass) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'FAIL: signing-key table lacks RLS'; END IF;

 blocked:=false;
 BEGIN
  INSERT INTO public.messaging_devices(id,user_id,public_key_jwk,key_algorithm)
   VALUES(first_id,u2,jsonb_build_object('kty','EC','crv','P-256'),
     'ECDH-P256');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: first-device INSERT accepted'; END IF;
 IF EXISTS(SELECT 1 FROM public.messaging_devices WHERE id=first_id)
 THEN RAISE EXCEPTION 'FAIL: failed first-device insert persisted'; END IF;

 -- Key bootstrap through existing historical unverified device also denied.
 blocked:=false;
 BEGIN
  INSERT INTO public.messaging_device_signing_keys(
    device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
  VALUES(historic,u2,jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('J',43),'y',repeat('K',43)),
    clock_timestamp(),'audited_recovery');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: historical first signer became verified'; END IF;

 -- A revoked sole trusted signing key cannot be used to create more devices.
 blocked:=false;
 BEGIN
  UPDATE public.messaging_device_signing_keys
    SET revoked_at=clock_timestamp() WHERE device_id=trusted;
  INSERT INTO public.messaging_devices(
    id,user_id,public_key_jwk,key_algorithm)
  VALUES('34343434-3434-4434-8434-343434343434',u1,
    jsonb_build_object('kty','EC','crv','P-256'),'ECDH-P256');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: revoked signing key approved new device'; END IF;

 -- Existing key, owner and algorithm cannot be switched silently.
 blocked:=false;
 BEGIN
  UPDATE public.messaging_devices
  SET user_id=u2 WHERE id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: cross-account device rebinding'; END IF;

 blocked:=false;
 BEGIN
  UPDATE public.messaging_devices
  SET public_key_jwk=jsonb_build_object('kty','EC','crv','P-256','x','x')
  WHERE id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: ECDH key substitution'; END IF;

 blocked:=false;
 BEGIN
  UPDATE public.messaging_device_signing_keys
  SET signing_public_key_jwk=jsonb_build_object('kty','EC','crv','P-256','x','x')
  WHERE device_id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: signing key substitution'; END IF;

 blocked:=false;
 BEGIN
  UPDATE public.messaging_device_signing_keys
  SET verified_at=clock_timestamp() WHERE device_id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: verified timestamp rewrite'; END IF;

 blocked:=false;
 BEGIN
  UPDATE public.messaging_device_signing_keys
    SET revoked_at=clock_timestamp() WHERE device_id=trusted;
  UPDATE public.messaging_device_signing_keys
    SET revoked_at=NULL WHERE device_id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: signer silent unrevocation accepted'; END IF;

 blocked:=false;
 BEGIN
  UPDATE public.messaging_devices
    SET revoked_at=clock_timestamp() WHERE id=trusted;
  UPDATE public.messaging_devices
    SET revoked_at=NULL WHERE id=trusted;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: device silent unrevocation accepted'; END IF;

 IF (SELECT count(*) FROM public.messaging_devices WHERE user_id=u2)<>1
 OR (SELECT count(*) FROM public.messaging_device_signing_keys
     WHERE user_id=u2 AND verified_at IS NOT NULL)<>0
 OR (SELECT count(*) FROM public.messaging_devices WHERE user_id=u1)<>1
 OR (SELECT count(*) FROM public.messaging_device_signing_keys
     WHERE device_id=trusted AND revoked_at IS NULL)<>1
 THEN RAISE EXCEPTION 'FAIL: negative test modified identity state'; END IF;

 RAISE NOTICE 'PASS: first trusted device/signer, revoked signer, cross-account/key swap, timestamp and reactivation all rejected';
END $test$;
