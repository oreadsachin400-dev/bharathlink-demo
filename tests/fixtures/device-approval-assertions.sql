-- Disposable GitHub CI Postgres only; do not execute against BharathLink-20-TEST.
DO $test$
DECLARE
  uid uuid:='11111111-1111-4111-8111-111111111111';
  req uuid:='33333333-3333-4333-8333-333333333333';
  approver uuid:='22222222-2222-4222-8222-222222222222';
  ctx jsonb;
  digest text;
  result jsonb;
BEGIN
  IF has_function_privilege('anon','public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)','EXECUTE')
    OR has_function_privilege('authenticated','public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)','EXECUTE')
    OR has_function_privilege('anon','public.bl20_device_approval_context(uuid,uuid,uuid)','EXECUTE')
    OR has_function_privilege('authenticated','public.bl20_device_approval_context(uuid,uuid,uuid)','EXECUTE')
    OR NOT has_function_privilege('service_role','public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)','EXECUTE')
  THEN RAISE EXCEPTION 'FAIL: incorrect RPC privileges'; END IF;

  IF public.bl20_device_approval_context(
    '99999999-9999-4999-8999-999999999999',req,approver) IS NOT NULL
  THEN RAISE EXCEPTION 'FAIL wrong account context'; END IF;
  IF public.bl20_device_approval_context(
    '99999999-9999-4999-8999-999999999999',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',approver) IS NOT NULL
  THEN RAISE EXCEPTION 'FAIL first device trusted automatically'; END IF;

  ctx:=public.bl20_device_approval_context(uid,req,approver);
  IF ctx IS NULL THEN RAISE EXCEPTION 'FAIL trusted context missing'; END IF;
  digest:=encode(extensions.digest(convert_to(ctx->>'payload','UTF8'),'sha256'),'hex');

  -- Invalid proof cannot authorize an insertion.
  BEGIN
    PERFORM public.bl20_commit_device_approval(uid,req,approver,repeat('0',64),ctx->>'signingKeyDigest');
    RAISE EXCEPTION 'FAIL invalid payload digest accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM public.bl20_commit_device_approval(uid,req,approver,digest,repeat('0',64));
    RAISE EXCEPTION 'FAIL substituted signing key accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM public.bl20_commit_device_approval(uid,req,approver,NULL,NULL);
    RAISE EXCEPTION 'FAIL null digest accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  IF EXISTS (SELECT 1 FROM public.messaging_devices
     WHERE id='44444444-4444-4444-8444-444444444444')
  THEN RAISE EXCEPTION 'FAIL invalid proof inserted device'; END IF;

  -- The SQL commit is called *only after* Edge has verified ECDSA;
  -- these tests verify atomicity and DB-side bind/replay enforcement, not ECDSA.
  result:=public.bl20_commit_device_approval(uid,req,approver,digest,ctx->>'signingKeyDigest');
  IF result->>'approved'<>'true' THEN RAISE EXCEPTION 'FAIL valid transaction'; END IF;
  IF (SELECT status FROM public.messaging_device_enrollment_requests WHERE request_id=req)<>'approved'
    OR (SELECT consumed_at FROM public.messaging_device_enrollment_requests WHERE request_id=req) IS NULL
    OR (SELECT count(*) FROM public.messaging_devices WHERE id='44444444-4444-4444-8444-444444444444')<>1
    OR (SELECT count(*) FROM public.messaging_device_signing_keys
          WHERE device_id='44444444-4444-4444-8444-444444444444')<>1
  THEN RAISE EXCEPTION 'FAIL incomplete atomic approval'; END IF;
  BEGIN
    PERFORM public.bl20_commit_device_approval(uid,req,approver,digest,ctx->>'signingKeyDigest');
    RAISE EXCEPTION 'FAIL request replay accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'PASS: SQL synthetic authorization/atomicity/replay/permission tests';
END;
$test$;

-- Confirm revocation blocks new request even with previous verified signing key.
INSERT INTO public.messaging_device_enrollment_requests
  (request_id,user_id,proposed_device_id,proposed_public_key_jwk,proposed_signing_public_key_jwk)
VALUES
  ('55555555-5555-4555-8555-555555555555',
   '11111111-1111-4111-8111-111111111111',
   '66666666-6666-4666-8666-666666666666',
   '{"kty":"EC","crv":"P-256"}','{"kty":"EC","crv":"P-256"}');
UPDATE public.messaging_device_signing_keys SET revoked_at=now()
 WHERE device_id='22222222-2222-4222-8222-222222222222';
DO $rev$
BEGIN
 IF public.bl20_device_approval_context(
  '11111111-1111-4111-8111-111111111111',
  '55555555-5555-4555-8555-555555555555',
  '22222222-2222-4222-8222-222222222222') IS NOT NULL
 THEN RAISE EXCEPTION 'FAIL revoked approver accepted'; END IF;
 RAISE NOTICE 'PASS: revoked approver denied';
END;
$rev$;
