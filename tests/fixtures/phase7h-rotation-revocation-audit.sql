-- Phase 7H: automatic pending-governance veto on issuer rotation/revocation.
-- CI-only disposable database; NO first-device approval.
DO $test$
DECLARE
 u uuid:='99999999-9999-4999-8999-999999999999';
 pin bl20_issuer_pin_v1_private.receipt_pins%ROWTYPE;
 pending bl20_first_device_v1_private.review_intents%ROWTYPE;
 initial_sha text;
 new_sha text;
 rejected boolean;
 device_total bigint;
BEGIN
 SELECT * INTO pin FROM bl20_issuer_pin_v1_private.receipt_pins;
 SELECT * INTO pending FROM bl20_first_device_v1_private.review_intents;
 IF pin.challenge_id IS NULL OR pending.id IS NULL
    OR pending.state<>'governance_pending_review_only'
 THEN RAISE EXCEPTION 'FAIL: require genuine pinned pending governance fixture'; END IF;
 device_total:=(SELECT count(*) FROM public.messaging_devices);
 initial_sha:=pin.issuer_public_key_sha256;

 -- The registry CAN rotate for operational reasons, but that immediately
 -- vetoes all pending intents for this issuer. History remains pinned.
 UPDATE bl20_recovery_v1_private.issuers
 SET public_jwk=pg_catalog.jsonb_set(
  public_jwk,'{x}',pg_catalog.to_jsonb(repeat('Z',43)))
 WHERE issuer_id=pin.issuer_id;
 IF (SELECT state FROM bl20_first_device_v1_private.review_intents WHERE id=pending.id)
      <>'governance_vetoed'
 OR (SELECT veto_reason FROM bl20_first_device_v1_private.review_intents WHERE id=pending.id)
      <>'security_hold'
 OR (SELECT count(*) FROM bl20_first_device_v1_private.audit_events
     WHERE intent_id=pending.id AND event_kind='intent_vetoed')<>1
 OR (SELECT count(*) FROM bl20_issuer_pin_v1_private.issuer_events
     WHERE issuer_id=pin.issuer_id AND event_kind='key_rotated')<>1
 THEN RAISE EXCEPTION 'FAIL: rotation did not veto governance and record audit'; END IF;
 IF (SELECT issuer_public_key_sha256 FROM bl20_issuer_pin_v1_private.receipt_pins
     WHERE challenge_id=pin.challenge_id)<>initial_sha
 OR (SELECT issuer_public_jwk FROM bl20_issuer_pin_v1_private.receipt_pins
     WHERE challenge_id=pin.challenge_id) IS DISTINCT FROM pin.issuer_public_jwk
 THEN RAISE EXCEPTION 'FAIL: historical signed key pin mutated'; END IF;
 SELECT bl20_issuer_pin_v1_private.key_fingerprint(public_jwk)
 INTO new_sha FROM bl20_recovery_v1_private.issuers
 WHERE issuer_id=pin.issuer_id;
 IF new_sha=initial_sha THEN RAISE EXCEPTION 'FAIL: test issuer key did not rotate'; END IF;

 -- Revocation is audit-logged, without a second veto on already vetoed intents.
 UPDATE bl20_recovery_v1_private.issuers
 SET revoked_at=pg_catalog.clock_timestamp()
 WHERE issuer_id=pin.issuer_id;
 IF (SELECT count(*) FROM bl20_issuer_pin_v1_private.issuer_events
       WHERE issuer_id=pin.issuer_id AND event_kind='issuer_revoked')<>1
 OR (SELECT count(*) FROM bl20_first_device_v1_private.audit_events
     WHERE intent_id=pending.id AND event_kind='intent_vetoed')<>1
 THEN RAISE EXCEPTION 'FAIL: issuer revocation audit or veto duplicated'; END IF;

 rejected:=false;
 BEGIN
  UPDATE bl20_recovery_v1_private.issuers
  SET revoked_at=NULL WHERE issuer_id=pin.issuer_id;
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: previously revoked issuer reactivated'; END IF;

 rejected:=false;
 BEGIN
  UPDATE bl20_issuer_pin_v1_private.issuer_events
  SET event_kind='key_rotated' WHERE event_kind='issuer_revoked';
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: issuer audit history modifiable'; END IF;
 rejected:=false;
 BEGIN
  DELETE FROM bl20_issuer_pin_v1_private.issuer_events;
 EXCEPTION WHEN insufficient_privilege THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL: issuer audit deleted'; END IF;

 IF (SELECT count(*) FROM public.messaging_devices)<>device_total
    OR EXISTS(SELECT 1 FROM public.messaging_devices WHERE user_id=u)
 THEN RAISE EXCEPTION 'FAIL: issuer rotation granted device trust'; END IF;
 IF (SELECT count(*) FROM bl20_issuer_pin_v1_private.issuer_events)<>2
 OR (SELECT count(*) FROM bl20_first_device_v1_private.audit_events)<>2
 THEN RAISE EXCEPTION 'FAIL: expected pin rotation/revocation and governance audit counts'; END IF;
 RAISE NOTICE 'PASS: issuer rotation vetoed pending intent; revocation locked, immutable pin/audit, no first-device approval';
END;
$test$;
