-- Phase7G governance revocation and audit: disposable CI PostgreSQL only.
DO $test$
DECLARE
 v_id uuid;
 v_payload jsonb;
 denied boolean;
 before_devices bigint;
BEGIN
 SELECT id INTO v_id FROM bl20_first_device_v1_private.review_intents;
 IF v_id IS NULL THEN RAISE EXCEPTION 'FAIL: no pending governance intent'; END IF;
 before_devices:=(SELECT count(*) FROM public.messaging_devices);
 denied:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.veto_review_intent(v_id,'unsafe_unlisted_reason');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: arbitrary veto reason accepted'; END IF;
 v_payload:=bl20_first_device_v1_private.veto_review_intent(v_id,'consent_withdrawn');
 IF v_payload->>'vetoRecorded'<>'true'
 OR v_payload->>'deviceApproved'<>'false'
 OR v_payload->>'trustedDevice'<>'false'
 OR v_payload->>'e2eeV2Ready'<>'false'
 THEN RAISE EXCEPTION 'FAIL: veto must be non-approval'; END IF;
 IF (SELECT state FROM bl20_first_device_v1_private.review_intents WHERE id=v_id)
    <>'governance_vetoed'
 OR (SELECT veto_reason FROM bl20_first_device_v1_private.review_intents WHERE id=v_id)
    <>'consent_withdrawn'
 OR (SELECT count(*) FROM bl20_first_device_v1_private.audit_events
     WHERE intent_id=v_id AND event_kind='intent_staged')<>1
 OR (SELECT count(*) FROM bl20_first_device_v1_private.audit_events
     WHERE intent_id=v_id AND event_kind='intent_vetoed')<>1
 THEN RAISE EXCEPTION 'FAIL: missing audit record or veto state'; END IF;
 denied:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.veto_review_intent(v_id,'security_hold');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL: double veto/replay accepted'; END IF;
 IF (SELECT count(*) FROM public.messaging_devices)<>before_devices
 OR EXISTS(SELECT 1 FROM public.messaging_devices
    WHERE id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid)
 THEN RAISE EXCEPTION 'FAIL: governance veto touched device records'; END IF;
 IF EXISTS(SELECT 1 FROM bl20_first_device_v1_private.review_intents
    WHERE state NOT IN ('governance_pending_review_only','governance_vetoed'))
 THEN RAISE EXCEPTION 'FAIL: trusted/approved governance state detected'; END IF;
 RAISE NOTICE 'PASS: Phase7G consent withdrawal recorded once with audit; no device approval';
END;
$test$;
