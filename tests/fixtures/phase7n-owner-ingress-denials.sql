-- Phase7N disposable SQL regression. Execute AFTER Phase7M signed-fixture
-- creates exactly one historical review receipt. NO live DB access.
DO $test$
DECLARE
 before_receipts bigint;
 before_events bigint;
 denied boolean;
 msg text;
 b uuid:='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
BEGIN
 SELECT count(*) INTO before_receipts FROM bl20_review_ledger_v1_private.receipts;
 SELECT count(*) INTO before_events FROM bl20_review_ledger_v1_private.events;
 IF before_receipts<>1 OR before_events<>1
 THEN RAISE EXCEPTION 'Expected exactly one historical test receipt'; END IF;

 -- Old owner function used to accept valid-looking hashes without signatures.
 denied:=false;
 BEGIN
  PERFORM bl20_review_ledger_v1_private.stage_review_evidence(
   b, repeat('1',64),repeat('2',64),
   repeat('3',64),repeat('4',64),
   repeat('5',64),repeat('6',64),
   repeat('8',64),clock_timestamp()+interval '2 minutes');
 EXCEPTION WHEN insufficient_privilege THEN
  GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT;
  IF msg LIKE 'Review evidence hard stop:%' THEN denied:=true; END IF;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: privileged old hash-only RPC still accepts input'; END IF;

 -- INSERT directly into receipts as owner, bypassing old RPC.
 denied:=false;
 BEGIN
  INSERT INTO bl20_review_ledger_v1_private.receipts(
    intent_id,user_id,session_id,request_id,challenge_id,device_id,
    candidate_proof_id,issuer_key_sha256,ecdh_key_sha256,signing_key_sha256,
    reviewed_evidence_sha256,reviewer_a,reviewer_b,
    reviewer_a_key_sha256,reviewer_b_key_sha256,
    reviewer_a_signature_sha256,reviewer_b_signature_sha256,
    reviewer_a_payload_sha256,reviewer_b_payload_sha256,
    nonce_sha256,expires_at)
  SELECT id,user_id,session_id,request_id,challenge_id,device_id,
    candidate_proof_id,issuer_key_sha256,ecdh_key_sha256,signing_key_sha256,
    reviewed_evidence_sha256,reviewer_a,reviewer_b,
    repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),
    repeat('5',64),repeat('6',64),repeat('8',64),
    clock_timestamp()+interval '2 minutes'
  FROM bl20_first_device_v1_private.review_intents WHERE id=b;
 EXCEPTION WHEN insufficient_privilege THEN
  GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT;
  IF msg LIKE 'Review evidence hard stop:%' THEN denied:=true; END IF;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: direct owner receipt INSERT bypassed hard stop'; END IF;

 -- The audit log is also sealed against post-hoc fabricated events.
 denied:=false;
 BEGIN
  INSERT INTO bl20_review_ledger_v1_private.events(intent_id,event_kind)
  VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','review_evidence_staged_only');
 EXCEPTION WHEN insufficient_privilege THEN
  GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT;
  IF msg LIKE 'Review evidence hard stop:%' THEN denied:=true; END IF;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: direct owner event INSERT bypassed hard stop'; END IF;

 -- Existing historical receipt and event must not be overwritten or erased.
 denied:=false;
 BEGIN
  DELETE FROM bl20_review_ledger_v1_private.receipts
   WHERE intent_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 EXCEPTION WHEN insufficient_privilege THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: historical receipt deletion permitted'; END IF;

 denied:=false;
 BEGIN
  UPDATE bl20_review_ledger_v1_private.events
  SET event_kind='review_evidence_staged_only';
 EXCEPTION WHEN insufficient_privilege THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: historical audit rewrite permitted'; END IF;

 IF (SELECT count(*) FROM bl20_review_ledger_v1_private.receipts)<>before_receipts
 OR (SELECT count(*) FROM bl20_review_ledger_v1_private.events)<>before_events
 OR (SELECT count(*) FROM public.messaging_devices)<>0
 THEN RAISE EXCEPTION 'FAIL: evidence history changed or device registered'; END IF;

 IF has_schema_privilege('anon','bl20_review_ledger_v1_private','USAGE')
 OR has_schema_privilege('authenticated','bl20_review_ledger_v1_private','USAGE')
 OR has_schema_privilege('service_role','bl20_review_ledger_v1_private','USAGE')
 OR has_function_privilege('service_role',
   'bl20_review_ledger_v1_private.stage_review_evidence(uuid,text,text,text,text,text,text,text,timestamptz)',
   'EXECUTE')
 THEN RAISE EXCEPTION 'FAIL: untrusted API role gained privileges'; END IF;
 RAISE NOTICE 'PASS Phase7N: owner RPC and direct INSERT hard-stopped; existing audit immutable, zero devices';
END;
$test$;
