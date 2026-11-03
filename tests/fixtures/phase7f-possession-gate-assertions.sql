-- Phase 7F synthetic-only checks, run in disposable Postgres.
-- Never execute against BharathLink-20-TEST or production.
DO $test$
DECLARE
 uid uuid:='11111111-1111-4111-8111-111111111111';
 outsider uuid:='99999999-9999-4999-8999-999999999999';
 rid uuid:='33333333-3333-4333-8333-333333333333';
 approver uuid:='22222222-2222-4222-8222-222222222222';
 c jsonb; ctx jsonb; p_id uuid; digest text; r jsonb;
 v_ecdh jsonb; v_sign jsonb;
 v_orig_created timestamptz; v_orig_consumed timestamptz;
 v_orig_expires timestamptz;
 denied boolean;
BEGIN
 IF has_function_privilege('service_role',
      'public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)','EXECUTE')
  OR has_function_privilege('anon',
      'public.bl20_commit_device_approval_v2(uuid,uuid,uuid,uuid,text,text)','EXECUTE')
  OR has_function_privilege('authenticated',
      'public.bl20_commit_device_approval_v2(uuid,uuid,uuid,uuid,text,text)','EXECUTE')
  OR NOT has_function_privilege('service_role',
      'public.bl20_commit_device_approval_v2(uuid,uuid,uuid,uuid,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'FAIL: legacy or new RPC grant boundary'; END IF;

 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=2 WHERE request_id=rid;
 SELECT proposed_public_key_jwk,proposed_signing_public_key_jwk
 INTO v_ecdh,v_sign FROM public.messaging_device_enrollment_requests
 WHERE request_id=rid;
 ctx:=public.bl20_device_approval_context(uid,rid,approver);
 IF ctx IS NULL THEN RAISE EXCEPTION 'FAIL: synthetic trusted approver context missing'; END IF;
 digest:=pg_catalog.encode(extensions.digest(
  pg_catalog.convert_to(ctx->>'payload','UTF8'),'sha256'),'hex');

 -- A preexisting trusted approver alone is not enough.
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: no possession proof approved'; END IF;

 c:=public.bl20_candidate_proof_start(uid,
  '44444444-4444-4444-8444-444444444444',v_ecdh,v_sign);
 p_id:=(c->>'proofId')::uuid;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: pending (unproven) candidate approved'; END IF;

 PERFORM public.bl20_candidate_proof_finish(uid,p_id,pg_catalog.encode(
   extensions.digest(pg_catalog.convert_to(c->>'payload','UTF8'),'sha256'),'hex'));
 SELECT created_at,consumed_at,expires_at INTO
   v_orig_created,v_orig_consumed,v_orig_expires
 FROM bl20_candidate_v1_private.proofs WHERE id=p_id;

 -- Account/key/device/protocol binding and time freshness all required.
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(outsider,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: cross-account approval'; END IF;

 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    repeat('0',64),ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: forged approver digest'; END IF;

 UPDATE public.messaging_device_enrollment_requests
 SET proposed_signing_public_key_jwk=pg_catalog.jsonb_set(
      proposed_signing_public_key_jwk,'{x}',pg_catalog.to_jsonb(repeat('Z',43)))
 WHERE request_id=rid;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: signing key substitution'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET proposed_signing_public_key_jwk=v_sign WHERE request_id=rid;

 UPDATE public.messaging_device_enrollment_requests
 SET proposed_public_key_jwk=pg_catalog.jsonb_set(
      proposed_public_key_jwk,'{x}',pg_catalog.to_jsonb(repeat('Z',43)))
 WHERE request_id=rid;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: ECDH key substitution'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET proposed_public_key_jwk=v_ecdh WHERE request_id=rid;

 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=1 WHERE request_id=rid;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: protocol downgrade accepted'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=2 WHERE request_id=rid;

 UPDATE bl20_candidate_v1_private.proofs
 SET created_at=pg_catalog.clock_timestamp()-interval '21 minutes',
     expires_at=pg_catalog.clock_timestamp()-interval '17 minutes',
     consumed_at=pg_catalog.clock_timestamp()-interval '20 minutes'
 WHERE id=p_id;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: stale candidate proof accepted'; END IF;
 UPDATE bl20_candidate_v1_private.proofs
 SET created_at=v_orig_created,consumed_at=v_orig_consumed,expires_at=v_orig_expires
 WHERE id=p_id;

 IF EXISTS(SELECT 1 FROM public.messaging_devices
   WHERE id='44444444-4444-4444-8444-444444444444')
 THEN RAISE EXCEPTION 'FAIL: unauthorized tests inserted device'; END IF;

 -- Synthetic SQL positive path: Edge ECDSA approval verification is tested elsewhere.
 r:=public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
   digest,ctx->>'signingKeyDigest');
 IF r->>'approved'<>'true' OR r->>'candidateProofBound'<>'true'
 THEN RAISE EXCEPTION 'FAIL: valid synthetic approval transaction'; END IF;
 IF (SELECT count(*) FROM bl20_candidate_v1_private.trusted_approval_links
   WHERE proof_id=p_id AND request_id=rid
   AND device_id='44444444-4444-4444-8444-444444444444')<>1
   OR (SELECT count(*) FROM public.messaging_device_signing_keys
    WHERE device_id='44444444-4444-4444-8444-444444444444')<>1
 THEN RAISE EXCEPTION 'FAIL: atomic approved device/proof link'; END IF;
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(uid,rid,approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: replay approved'; END IF;

 -- No verified signer in outsider account -> FIRST DEVICE MUST DENY.
 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=2
 WHERE request_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 denied:=false;
 BEGIN
  PERFORM public.bl20_commit_device_approval_v2(outsider,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',approver,p_id,
    digest,ctx->>'signingKeyDigest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: first device bootstrapped'; END IF;

 RAISE NOTICE 'PASS: Phase7F missing/unproven/stale/wrong-key/wrong-owner/downgrade denied; synthetic v2 atomic approval and replay';
END;
$test$;
