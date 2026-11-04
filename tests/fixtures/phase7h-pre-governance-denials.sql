-- Phase 7H: disposable Postgres-only negative tests *before* governance staging.
DO $test$
DECLARE
 u uuid:='99999999-9999-4999-8999-999999999999';
 sid uuid:='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
 cid uuid;
 pin bl20_issuer_pin_v1_private.receipt_pins%ROWTYPE;
 changed_key jsonb;
 rejected boolean;
 original_events integer;
BEGIN
 SELECT * INTO pin FROM bl20_issuer_pin_v1_private.receipt_pins;
 cid:=pin.challenge_id;
 IF cid IS NULL THEN RAISE EXCEPTION 'FAIL: no immutable pin'; END IF;
 IF has_function_privilege('service_role',
   'bl20_issuer_pin_v1_private.key_fingerprint(jsonb)','EXECUTE')
 OR has_function_privilege('anon',
   'public.bl20_recovery_v1_review_consume_v3(uuid,uuid,uuid,text,text,text)','EXECUTE')
 OR has_schema_privilege('authenticated','bl20_issuer_pin_v1_private','USAGE')
 THEN RAISE EXCEPTION 'FAIL: issuer pin API exposed'; END IF;
 IF (SELECT relrowsecurity FROM pg_class
     WHERE oid='bl20_issuer_pin_v1_private.receipt_pins'::regclass)
    IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'FAIL: pin table missing RLS'; END IF;

 rejected:=false;
 BEGIN
  UPDATE bl20_issuer_pin_v1_private.receipt_pins
   SET issuer_public_key_sha256=repeat('0',64) WHERE challenge_id=cid;
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: pin mutated'; END IF;
 rejected:=false;
 BEGIN
  DELETE FROM bl20_issuer_pin_v1_private.receipt_pins
  WHERE challenge_id=cid;
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: historical pin deleted'; END IF;

 -- Any SQL-level issuer public key rotation must block staging of this
 -- historical signed receipt when no longer matching its immutable pin.
 -- Both the attempted rotation and audit event are subtransaction-rolled-back.
 original_events:=(SELECT count(*) FROM bl20_issuer_pin_v1_private.issuer_events);
 SELECT pg_catalog.jsonb_set(i.public_jwk,'{x}',
  pg_catalog.to_jsonb(repeat('Z',43)))
 INTO changed_key FROM bl20_recovery_v1_private.issuers i
 WHERE i.issuer_id=pin.issuer_id;
 rejected:=false;
 BEGIN
  UPDATE bl20_recovery_v1_private.issuers
  SET public_jwk=changed_key WHERE issuer_id=pin.issuer_id;
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: rotated issuer accepted for old pin'; END IF;
 IF (SELECT count(*) FROM bl20_issuer_pin_v1_private.issuer_events)<>original_events
 THEN RAISE EXCEPTION 'FAIL: failed rotation not rolled back'; END IF;
 IF (SELECT count(*) FROM bl20_first_device_v1_private.review_intents)<>0
 THEN RAISE EXCEPTION 'FAIL: invalid issuer created pending intent'; END IF;

 -- A signed case whose evidence is tampered cannot be staged.
 rejected:=false;
 BEGIN
  UPDATE bl20_recovery_v1_private.receipts
  SET attestation_sha256=repeat('0',64) WHERE challenge_id=cid;
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: modified attestation receipt accepted'; END IF;

 -- A revoked issuer blocks even a genuine previously signed receipt.
 rejected:=false;
 BEGIN
  UPDATE bl20_recovery_v1_private.issuers
  SET revoked_at=clock_timestamp() WHERE issuer_id=pin.issuer_id;
  PERFORM bl20_first_device_v1_private.stage_review_intent(u,sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: revoked issuer accepted'; END IF;

 IF (SELECT count(*) FROM bl20_first_device_v1_private.review_intents)<>0
 OR (SELECT count(*) FROM public.messaging_devices WHERE user_id=u)<>0
 THEN RAISE EXCEPTION 'FAIL: denial accidentally approved device'; END IF;
 RAISE NOTICE 'PASS: immutable receipt pin, RLS, private grants, rotated/revoked issuer and corrupted receipt denied';
END;
$test$;
