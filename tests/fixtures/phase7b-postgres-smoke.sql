-- Real PostgreSQL smoke tests run ONLY in ephemeral GitHub Actions service.
-- Tests DB-issued canonical challenge, owner scoping, expiry, single-use.
DO $test$
DECLARE
 v_user uuid := '11111111-1111-4111-8111-111111111111';
 v_other uuid := '22222222-2222-4222-8222-222222222222';
 v_device uuid := '33333333-3333-4333-8333-333333333333';
 v_device2 uuid := '44444444-4444-4444-8444-444444444444';
 v_ecdh jsonb := jsonb_build_object('kty','EC','crv','P-256','x',repeat('A',43),'y',repeat('B',43));
 v_sign jsonb := jsonb_build_object('kty','EC','crv','P-256','x',repeat('C',43),'y',repeat('D',43));
 v_start jsonb;
 v_context jsonb;
 v_result jsonb;
 v_proof uuid;
 v_digest text;
 v_caught boolean;
BEGIN
 IF has_function_privilege('anon','public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)','EXECUTE')
   OR has_function_privilege('authenticated','public.bl20_candidate_proof_finish(uuid,uuid,text)','EXECUTE')
   OR NOT has_function_privilege('service_role','public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)','EXECUTE')
 THEN RAISE EXCEPTION 'FAIL: RPC grant boundary'; END IF;
 IF EXISTS (SELECT 1 FROM public.messaging_devices)
 THEN RAISE EXCEPTION 'FAIL: dirty fixture'; END IF;

 v_start := public.bl20_candidate_proof_start(v_user,v_device,v_ecdh,v_sign);
 v_proof := (v_start->>'proofId')::uuid;
 IF v_start->>'serverApproved' <> 'false' OR v_start->>'deviceId'<>v_device::text
  OR v_start->>'userId'<>v_user::text OR (v_start->>'payload') NOT LIKE
   'BHARATHLINK_CANDIDATE_POSSESSION_V1' || E'\n' || v_user::text || E'\n%'
 THEN RAISE EXCEPTION 'FAIL: server challenge or trust semantics'; END IF;

 -- Duplicate pending challenge rejected under the ownership lock.
 v_caught := false;
 BEGIN
   PERFORM public.bl20_candidate_proof_start(v_user,v_device,v_ecdh,v_sign);
 EXCEPTION WHEN unique_violation THEN v_caught := true;
 END;
 IF NOT v_caught THEN RAISE EXCEPTION 'FAIL: duplicate pending request accepted'; END IF;

 -- Cross-account must not get challenge context or consume proof.
 IF public.bl20_candidate_proof_context(v_other,v_proof) IS NOT NULL
 THEN RAISE EXCEPTION 'FAIL: cross-account context exposure'; END IF;
 v_caught := false;
 BEGIN
   PERFORM public.bl20_candidate_proof_finish(v_other,v_proof,repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN v_caught := true;
 END;
 IF NOT v_caught THEN RAISE EXCEPTION 'FAIL: cross-account consume'; END IF;

 v_context := public.bl20_candidate_proof_context(v_user,v_proof);
 IF v_context IS NULL OR v_context->>'payload'<>v_start->>'payload'
    OR v_context->>'deviceId'<>v_device::text
 THEN RAISE EXCEPTION 'FAIL: server context not identical'; END IF;

 -- A forged client-supplied digest cannot consume.
 v_caught := false;
 BEGIN
   PERFORM public.bl20_candidate_proof_finish(v_user,v_proof,repeat('0',64));
 EXCEPTION WHEN insufficient_privilege THEN v_caught := true;
 END;
 IF NOT v_caught THEN RAISE EXCEPTION 'FAIL: wrong payload digest accepted'; END IF;

 v_digest := encode(extensions.digest(convert_to(v_context->>'payload','UTF8'),'sha256'),'hex');
 v_result := public.bl20_candidate_proof_finish(v_user,v_proof,v_digest);
 IF v_result->>'possessionProven'<>'true'
   OR v_result->>'serverApproved'<>'false'
   OR v_result->>'trustedDevice'<>'false'
   OR v_result->>'e2eeV2Ready'<>'false'
 THEN RAISE EXCEPTION 'FAIL: possession must never imply trust'; END IF;
 IF public.bl20_candidate_proof_context(v_user,v_proof) IS NOT NULL
 THEN RAISE EXCEPTION 'FAIL: consumed proof still visible'; END IF;
 v_caught := false;
 BEGIN
   PERFORM public.bl20_candidate_proof_finish(v_user,v_proof,v_digest);
 EXCEPTION WHEN insufficient_privilege THEN v_caught := true;
 END;
 IF NOT v_caught THEN RAISE EXCEPTION 'FAIL: replay accepted'; END IF;

 -- Simulate a past challenge respecting the 5-minute table constraint.
 v_start := public.bl20_candidate_proof_start(v_user,v_device2,v_ecdh,v_sign);
 v_proof := (v_start->>'proofId')::uuid;
 UPDATE bl20_candidate_v1_private.proofs
  SET created_at = clock_timestamp()-interval '10 minutes',
      expires_at = clock_timestamp()-interval '6 minutes'
 WHERE id=v_proof;
 IF public.bl20_candidate_proof_context(v_user,v_proof) IS NOT NULL
 THEN RAISE EXCEPTION 'FAIL: expired context accepted'; END IF;
 v_caught := false;
 BEGIN
  PERFORM public.bl20_candidate_proof_finish(v_user,v_proof,repeat('0',64));
 EXCEPTION WHEN insufficient_privilege THEN v_caught := true;
 END;
 IF NOT v_caught THEN RAISE EXCEPTION 'FAIL: expired challenge consumed'; END IF;

 IF EXISTS (SELECT 1 FROM public.messaging_devices)
 THEN RAISE EXCEPTION 'FAIL: trusted device state modified'; END IF;
 RAISE NOTICE 'PASS: DB-generated challenge, owner, digest, expiry, single consume, no trust';
END $test$;
