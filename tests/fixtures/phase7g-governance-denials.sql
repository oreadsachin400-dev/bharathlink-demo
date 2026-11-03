-- PHASE 7G disposable Postgres-only negative authorization/governance tests.
-- Existing Phase 5 fixture must have one genuinely synthetically signed receipt.
DO $test$
DECLARE
 u uuid:='99999999-9999-4999-8999-999999999999';
 sid uuid:='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
 rid uuid:='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 cid uuid;
 pid uuid;
 caseid uuid;
 original_key jsonb;
 original_sha text;
 saved_consent timestamptz;
 saved_session_exp timestamptz;
 before_devices int;
 failed boolean;
BEGIN
 SELECT challenge_id,case_id,payload_sha256 INTO cid,caseid,original_sha
 FROM bl20_recovery_v1_private.receipts WHERE user_id=u LIMIT 1;
 IF cid IS NULL THEN RAISE EXCEPTION 'FAIL: missing signed review receipt from Phase 5'; END IF;
 SELECT candidate_proof_id INTO pid
 FROM bl20_recovery_v1_private.challenges WHERE id=cid;
 before_devices:=(SELECT count(*) FROM public.messaging_devices);
 IF EXISTS(SELECT 1 FROM bl20_first_device_v1_private.review_intents)
 THEN RAISE EXCEPTION 'FAIL: governance table must start empty'; END IF;
 IF has_function_privilege('anon',
    'bl20_first_device_v1_private.stage_review_intent(uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('authenticated',
    'bl20_first_device_v1_private.stage_review_intent(uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('service_role',
    'bl20_first_device_v1_private.stage_review_intent(uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('service_role',
    'bl20_first_device_v1_private.veto_review_intent(uuid,text)','EXECUTE')
 OR has_schema_privilege('service_role','bl20_first_device_v1_private','USAGE')
 THEN RAISE EXCEPTION 'FAIL: public or service role exposed to private governance'; END IF;
 IF EXISTS(SELECT 1 FROM information_schema.columns
    WHERE table_schema='bl20_first_device_v1_private'
      AND table_name='review_intents'
      AND column_name IN ('device_approved','trusted_device','e2ee_v2_ready'))
 THEN RAISE EXCEPTION 'FAIL: governance table must have no trust-state promotion'; END IF;

 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=3 WHERE request_id=rid;

 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(
    '11111111-1111-4111-8111-111111111111',sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL wrong account'; END IF;

 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(
    u,'ffffffff-ffff-4fff-8fff-ffffffffffff',cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL wrong session'; END IF;

 SELECT not_after INTO saved_session_exp FROM auth.sessions WHERE id=sid;
 UPDATE auth.sessions SET not_after=clock_timestamp()-interval '1 minute' WHERE id=sid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL expired session'; END IF;
 UPDATE auth.sessions SET not_after=saved_session_exp WHERE id=sid;

 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=1 WHERE request_id=rid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL legacy enrollment protocol downgrade'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=3 WHERE request_id=rid;

 UPDATE bl20_recovery_v1_private.issuers
 SET revoked_at=clock_timestamp()
 WHERE issuer_id='SYNTHETIC_CI_ONLY_NOT_TRUSTED';
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL revoked independent issuer'; END IF;
 UPDATE bl20_recovery_v1_private.issuers
 SET revoked_at=NULL WHERE issuer_id='SYNTHETIC_CI_ONLY_NOT_TRUSTED';

 UPDATE bl20_recovery_v1_private.cases
 SET state='revoked' WHERE id=caseid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL revoked independent review'; END IF;
 UPDATE bl20_recovery_v1_private.cases
 SET state='independently_verified' WHERE id=caseid;

 SELECT consent_at INTO saved_consent
 FROM bl20_recovery_v1_private.cases WHERE id=caseid;
 UPDATE bl20_recovery_v1_private.cases
 SET consent_at=clock_timestamp()-interval '1 hour' WHERE id=caseid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL invalid user consent'; END IF;
 UPDATE bl20_recovery_v1_private.cases
 SET consent_at=saved_consent WHERE id=caseid;

 UPDATE bl20_recovery_v1_private.receipts
 SET payload_sha256=repeat('0',64) WHERE challenge_id=cid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL tampered review receipt hash'; END IF;
 UPDATE bl20_recovery_v1_private.receipts
 SET payload_sha256=original_sha WHERE challenge_id=cid;

 SELECT proposed_signing_public_key_jwk INTO original_key
 FROM public.messaging_device_enrollment_requests WHERE request_id=rid;
 UPDATE public.messaging_device_enrollment_requests
 SET proposed_signing_public_key_jwk =
   pg_catalog.jsonb_set(proposed_signing_public_key_jwk,
     '{x}',pg_catalog.to_jsonb(repeat('Z',43))) WHERE request_id=rid;
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL changed candidate signing key'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET proposed_signing_public_key_jwk=original_key WHERE request_id=rid;

 -- An existing verified signer means this is NOT a first-device path.
 INSERT INTO public.messaging_devices(id,user_id,public_key_jwk,key_algorithm)
 VALUES('10101010-1010-4010-8010-101010101010',u,
   jsonb_build_object('kty','EC','crv','P-256'),'ECDH-P256');
 INSERT INTO public.messaging_device_signing_keys
   (device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
 VALUES('10101010-1010-4010-8010-101010101010',u,
   jsonb_build_object('kty','EC','crv','P-256','x',repeat('A',43),
     'y',repeat('B',43)),clock_timestamp()-interval '1 hour','audited_recovery');
 failed:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN failed:=true; END;
 IF NOT failed THEN RAISE EXCEPTION 'FAIL existing trusted signer ignored'; END IF;
 DELETE FROM public.messaging_device_signing_keys WHERE user_id=u;
 DELETE FROM public.messaging_devices WHERE id='10101010-1010-4010-8010-101010101010';

 IF (SELECT count(*) FROM public.messaging_devices)<>before_devices
 OR EXISTS(SELECT 1 FROM bl20_first_device_v1_private.review_intents)
 THEN RAISE EXCEPTION 'FAIL negative test modified devices or created governance intent'; END IF;
 RAISE NOTICE 'PASS: 7G denied wrong account/session, expired session, legacy protocol, issuer/review revocation, invalid consent, tampered receipt, key substitution, trusted signer';
END;
$test$;
