-- Synthetic issuer is intentionally ABSENT from the staged SQL migration.
-- Test fixtures may insert one to exercise the private review state machine.
DO $test$
DECLARE
 u uuid:='99999999-9999-4999-8999-999999999999';
 sid uuid:='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
 bad_sid uuid:='ffffffff-ffff-4fff-8fff-ffffffffffff';
 reqid uuid:='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 proof_ctx jsonb; proof_id uuid; candidate_hash text;
 challenge jsonb; challenge_id uuid; review jsonb; payload_sha text; sig_sha text;
 count_before bigint;
 rec record;
BEGIN
 IF has_function_privilege('anon','public.bl20_recovery_v1_challenge_start(uuid,uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('authenticated','public.bl20_recovery_v1_review_context(uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('authenticated','public.bl20_recovery_v1_review_consume(uuid,uuid,uuid,text,text)','EXECUTE')
 OR has_function_privilege('anon','public.bl20_recovery_v1_review_payload(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,uuid,uuid,timestamptz,timestamptz)','EXECUTE')
 OR NOT has_function_privilege('service_role','public.bl20_recovery_v1_review_consume(uuid,uuid,uuid,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'FAIL public EXECUTE exposed'; END IF;
 IF (select count(*) FROM bl20_recovery_v1_private.issuers)<>0
 THEN RAISE EXCEPTION 'Migration must not auto-provision an issuer'; END IF;
 IF (SELECT relrowsecurity FROM pg_class WHERE oid='bl20_recovery_v1_private.challenges'::regclass) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'RLS missing'; END IF;
 SELECT * INTO rec FROM public.messaging_device_enrollment_requests WHERE request_id=reqid;
 IF NOT FOUND THEN RAISE EXCEPTION 'Missing synthetic candidate enrollment request'; END IF;
 proof_ctx:=public.bl20_candidate_proof_start(u,rec.proposed_device_id,
  rec.proposed_public_key_jwk,rec.proposed_signing_public_key_jwk);
 proof_id:=(proof_ctx->>'proofId')::uuid;
 candidate_hash:=encode(extensions.digest(convert_to(proof_ctx->>'payload','UTF8'),'sha256'),'hex');
 PERFORM public.bl20_candidate_proof_finish(u,proof_id,candidate_hash);
 IF (SELECT state FROM bl20_candidate_v1_private.proofs WHERE id=proof_id)<>'possession_proven'
 THEN RAISE EXCEPTION 'Candidate possession not committed'; END IF;
 count_before:=(SELECT count(*) FROM public.messaging_devices);
 -- Cannot mint a recovery challenge without an independently configured issuer.
 BEGIN
   PERFORM public.bl20_recovery_v1_challenge_start(u,sid,reqid,proof_id);
   RAISE EXCEPTION 'FAIL no-issuer recovery accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 INSERT INTO bl20_recovery_v1_private.issuers(issuer_id,public_jwk,independently_approved)
 VALUES('SYNTHETIC_CI_ONLY_NOT_TRUSTED',
  jsonb_build_object('kty','EC','crv','P-256',
                     'x',repeat('a',43),'y',repeat('b',43)),true);
 BEGIN
   PERFORM public.bl20_recovery_v1_challenge_start(u,bad_sid,reqid,proof_id);
   RAISE EXCEPTION 'FAIL another account session accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
   PERFORM public.bl20_recovery_v1_challenge_start(u,
     'dddddddd-dddd-4ddd-8ddd-dddddddddddd',reqid,proof_id);
   RAISE EXCEPTION 'FAIL expired session accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
   PERFORM public.bl20_recovery_v1_challenge_start(
      '11111111-1111-4111-8111-111111111111',sid,reqid,proof_id);
   RAISE EXCEPTION 'FAIL wrong account accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 challenge:=public.bl20_recovery_v1_challenge_start(u,sid,reqid,proof_id);
 challenge_id:=(challenge->>'challengeId')::uuid;
 IF challenge_id IS NULL OR (challenge->>'deviceApproved')::boolean<>false
 THEN RAISE EXCEPTION 'FAIL challenge should be nonapproval'; END IF;
 BEGIN
   PERFORM public.bl20_recovery_v1_challenge_start(u,sid,reqid,proof_id);
   RAISE EXCEPTION 'FAIL duplicate challenge accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF public.bl20_recovery_v1_review_context(u,sid,challenge_id) IS NOT NULL
 THEN RAISE EXCEPTION 'FAIL context exposed before verified review'; END IF;
 BEGIN
  INSERT INTO bl20_recovery_v1_private.cases
   (challenge_id,user_id,request_id,issuer_id,evidence_digest,
    reviewer_a,reviewer_b,consent_at,issued_at,expires_at,signature_base64url,
    state)
  VALUES(challenge_id,u,reqid,'SYNTHETIC_CI_ONLY_NOT_TRUSTED',repeat('e',64),
     u,'88888888-8888-4888-8888-888888888888',pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp(),
     pg_catalog.clock_timestamp()+interval '2 minutes',repeat('A',86),'independently_verified');
  RAISE EXCEPTION 'FAIL account holder self-reviewed';
 EXCEPTION WHEN check_violation THEN NULL; END;
 INSERT INTO bl20_recovery_v1_private.cases
   (challenge_id,user_id,request_id,issuer_id,evidence_digest,
    reviewer_a,reviewer_b,consent_at,issued_at,expires_at,
    signature_base64url,state)
 SELECT c.id,u,reqid,'SYNTHETIC_CI_ONLY_NOT_TRUSTED',repeat('e',64),
     '77777777-7777-4777-8777-777777777777'::uuid,
     '88888888-8888-4888-8888-888888888888'::uuid,
     c.created_at,pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp()+interval '2 minutes',repeat('A',86),
     'independently_verified'
 FROM bl20_recovery_v1_private.challenges c WHERE c.id=challenge_id;
 review:=public.bl20_recovery_v1_review_context(u,sid,challenge_id);
 IF review IS NULL OR review->>'deviceTrusted'<>'false'
 OR review->>'e2eeReady'<>'false'
 OR review->>'payload' NOT LIKE 'BHARATHLINK_INDEPENDENT_RECOVERY_REVIEW_V1'||E'\n%'
 THEN RAISE EXCEPTION 'FAIL reviewed payload missing'; END IF;
 IF split_part(review->>'payload',E'\n',6) <>
       (SELECT nonce::text FROM bl20_recovery_v1_private.challenges WHERE id=challenge_id)
 THEN RAISE EXCEPTION 'FAIL nonce missing from signed payload'; END IF;
 payload_sha:=encode(extensions.digest(convert_to(review->>'payload','UTF8'),'sha256'),'hex');
 sig_sha:=encode(extensions.digest(convert_to(review->>'signatureBase64Url','UTF8'),'sha256'),'hex');
 BEGIN
  PERFORM public.bl20_recovery_v1_review_consume(u,sid,challenge_id,repeat('0',64),sig_sha);
  RAISE EXCEPTION 'FAIL tampered payload accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM public.bl20_recovery_v1_review_consume(u,sid,challenge_id,payload_sha,repeat('0',64));
  RAISE EXCEPTION 'FAIL forged attestation digest accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM public.bl20_recovery_v1_review_consume(u,bad_sid,challenge_id,payload_sha,sig_sha);
  RAISE EXCEPTION 'FAIL wrong session accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF (SELECT count(*) FROM bl20_recovery_v1_private.receipts)<>0
 THEN RAISE EXCEPTION 'FAIL receipt created by invalid input'; END IF;
 IF (SELECT count(*) FROM public.messaging_devices)<>count_before
 THEN RAISE EXCEPTION 'FAIL review touched messaging_devices'; END IF;
 RAISE NOTICE 'PASS: no-issuer denial, session account binding, owner, canonical challenge, and invalid-hash rejection';
END;
$test$;
