-- DISPOSABLE CI PostgreSQL only. Do NOT execute against the live TEST project.
DO $test$
DECLARE
 u uuid:='11111111-1111-4111-8111-111111111111';
 other uuid:='99999999-9999-4999-8999-999999999999';
 device uuid:='77777777-7777-4777-8777-777777777777';
 keyA jsonb:=jsonb_build_object('kty','EC','crv','P-256','x',repeat('a',43),'y',repeat('b',43));
 keyB jsonb:=jsonb_build_object('kty','EC','crv','P-256','x',repeat('c',43),'y',repeat('d',43));
 context jsonb; proof uuid; hash text; result jsonb;
 before_devices bigint;
BEGIN
 IF has_function_privilege('anon','public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)','EXECUTE')
 OR has_function_privilege('authenticated','public.bl20_candidate_proof_finish(uuid,uuid,text)','EXECUTE')
 OR has_function_privilege('authenticated','public.bl20_candidate_proof_context(uuid,uuid)','EXECUTE')
 OR NOT has_function_privilege('service_role','public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)','EXECUTE')
 THEN RAISE EXCEPTION 'Permission exposure'; END IF;

 before_devices:=(SELECT count(*) FROM public.messaging_devices);
 BEGIN
  PERFORM public.bl20_candidate_proof_start(u,device,keyA,keyB||'{"d":"private"}'::jsonb);
  RAISE EXCEPTION 'Private JWK accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 context:=public.bl20_candidate_proof_start(u,device,keyA,keyB);
 proof:=(context->>'proofId')::uuid;
 IF proof IS NULL OR context->>'userId'<>u::text
    OR context->>'serverApproved'<>'false'
    OR context->>'payload' NOT LIKE 'BHARATHLINK_CANDIDATE_POSSESSION_V1'||E'\n%'
 THEN RAISE EXCEPTION 'Invalid canonical candidate challenge'; END IF;
 IF public.bl20_candidate_proof_context(other,proof) IS NOT NULL
 THEN RAISE EXCEPTION 'Wrong account can see proof'; END IF;
 BEGIN
  PERFORM public.bl20_candidate_proof_start(u,device,keyA,keyB);
  RAISE EXCEPTION 'Duplicate pending candidate accepted';
 EXCEPTION WHEN unique_violation THEN NULL;
 END;

 hash:=encode(extensions.digest(convert_to(context->>'payload','UTF8'),'sha256'),'hex');
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(other,proof,hash);
  RAISE EXCEPTION 'Wrong account committed';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(u,proof,repeat('0',64));
  RAISE EXCEPTION 'Tampered digest committed';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(u,proof,NULL);
  RAISE EXCEPTION 'Null digest committed';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF (SELECT count(*) FROM public.messaging_devices)<>before_devices
 THEN RAISE EXCEPTION 'Device was inserted without approval'; END IF;

 -- This is a synthetic SQL transaction test ONLY: the Edge layer verifies ECDSA.
 result:=public.bl20_candidate_proof_finish(u,proof,hash);
 IF result->>'possessionProven'<>'true'
    OR result->>'serverApproved'<>'false'
    OR result->>'trustedDevice'<>'false'
    OR result->>'e2eeV2Ready'<>'false' THEN
   RAISE EXCEPTION 'Incorrect proof status'; END IF;
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(u,proof,hash);
  RAISE EXCEPTION 'Replay accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF public.bl20_candidate_proof_context(u,proof) IS NOT NULL
 THEN RAISE EXCEPTION 'Consumed proof still valid'; END IF;
 IF (SELECT count(*) FROM public.messaging_devices)<>before_devices
 THEN RAISE EXCEPTION 'Proof escalated device trust'; END IF;

 RAISE NOTICE 'PASS: owner scope, canonical payload, private-key reject, payload binding, replay, and no trust escalation';
END;
$test$;

DO $exp$
DECLARE
 u uuid:='11111111-1111-4111-8111-111111111111';
 device uuid:='88888888-8888-4888-8888-888888888888';
 keyA jsonb:=jsonb_build_object('kty','EC','crv','P-256','x',repeat('a',43),'y',repeat('b',43));
 keyB jsonb:=jsonb_build_object('kty','EC','crv','P-256','x',repeat('c',43),'y',repeat('d',43));
 context jsonb; proof uuid;
BEGIN
 context:=public.bl20_candidate_proof_start(u,device,keyA,keyB);
 proof:=(context->>'proofId')::uuid;
 UPDATE bl20_candidate_v1_private.proofs
 SET expires_at=clock_timestamp()-interval '1 second'
 WHERE id=proof;
 IF public.bl20_candidate_proof_context(u,proof) IS NOT NULL
 THEN RAISE EXCEPTION 'Expired challenge still available'; END IF;
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(u,proof,repeat('a',64));
  RAISE EXCEPTION 'Expired candidate committed';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 RAISE NOTICE 'PASS: expiration denies context and finish';
END;
$exp$;
