-- Phase 7H-specific first-device governance preflight.
-- Unlike legacy Phase7G fixtures, never silently un-revokes an issuer.
DO $test$
DECLARE
 u uuid:='99999999-9999-4999-8999-999999999999';
 sid uuid:='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
 rid uuid:='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 cid uuid;
 rejected boolean;
BEGIN
 SELECT challenge_id INTO cid FROM bl20_issuer_pin_v1_private.receipt_pins;
 IF cid IS NULL THEN RAISE EXCEPTION 'FAIL: missing pinned review receipt'; END IF;
 IF EXISTS (SELECT 1 FROM bl20_first_device_v1_private.review_intents)
 THEN RAISE EXCEPTION 'FAIL: no prior governance intent expected'; END IF;
 UPDATE public.messaging_device_enrollment_requests
 SET approval_protocol_version=3 WHERE request_id=rid;
 IF NOT FOUND THEN RAISE EXCEPTION 'FAIL: missing synthetic first-device request'; END IF;

 rejected:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(
    '11111111-1111-4111-8111-111111111111',sid,cid);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: wrong account accepted'; END IF;

 rejected:=false;
 BEGIN
  PERFORM bl20_first_device_v1_private.stage_review_intent(
    u,'ffffffff-ffff-4fff-8fff-ffffffffffff',cid);
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: wrong session accepted'; END IF;

 IF EXISTS(SELECT 1 FROM bl20_recovery_v1_private.issuers
   WHERE revoked_at IS NOT NULL) THEN
  RAISE EXCEPTION 'FAIL: synthetic issuer already revoked'; END IF;
 IF (SELECT count(*) FROM bl20_issuer_pin_v1_private.receipt_pins)<>1
 OR EXISTS(SELECT 1 FROM public.messaging_devices WHERE user_id=u)
 THEN RAISE EXCEPTION 'FAIL: cross-account tests created device'; END IF;
 RAISE NOTICE 'PASS: Phase7H governance ready, account/session isolation, issuer pin unchanged';
END;
$test$;
