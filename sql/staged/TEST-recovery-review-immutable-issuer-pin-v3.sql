-- BharathLink Phase 7H -- STAGED, disposable PostgreSQL CI ONLY.
-- Never deploy to live TEST or production without an independent review.
-- Requires Phase 4+5 independent recovery and Phase 7G governance tables.
-- Purpose: pin EXACT issuer verification key at receipt consume time, track
-- issuer rotation/revocation and veto pending first-device governance.
-- DOES NOT approve devices or configure a real identity authority.
BEGIN;

CREATE SCHEMA bl20_issuer_pin_v1_private;
REVOKE ALL ON SCHEMA bl20_issuer_pin_v1_private
  FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl20_issuer_pin_v1_private.receipt_pins(
 challenge_id uuid PRIMARY KEY
   REFERENCES bl20_recovery_v1_private.receipts(challenge_id),
 case_id uuid NOT NULL UNIQUE
   REFERENCES bl20_recovery_v1_private.cases(id),
 issuer_id text NOT NULL
   REFERENCES bl20_recovery_v1_private.issuers(issuer_id),
 issuer_public_jwk jsonb NOT NULL,
 issuer_public_key_sha256 text NOT NULL
   CHECK(issuer_public_key_sha256 ~ '^[a-f0-9]{64}$'),
 attestation_sha256 text NOT NULL
   CHECK(attestation_sha256 ~ '^[a-f0-9]{64}$'),
 pinned_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE bl20_issuer_pin_v1_private.issuer_events(
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 issuer_id text NOT NULL,
 event_kind text NOT NULL
   CHECK(event_kind IN ('key_rotated','issuer_revoked','issuer_disabled')),
 old_key_sha256 text NOT NULL CHECK(old_key_sha256 ~ '^[a-f0-9]{64}$'),
 new_key_sha256 text NOT NULL CHECK(new_key_sha256 ~ '^[a-f0-9]{64}$'),
 event_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE bl20_issuer_pin_v1_private.receipt_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_issuer_pin_v1_private.issuer_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl20_issuer_pin_v1_private
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA bl20_issuer_pin_v1_private
 FROM PUBLIC,anon,authenticated,service_role;

-- This is a digest of canonical EC P-256 coordinates, NOT the jsonb::text hash.
CREATE FUNCTION bl20_issuer_pin_v1_private.key_fingerprint(p_key jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path TO ''
AS $fn$
 SELECT pg_catalog.encode(extensions.digest(
   pg_catalog.convert_to(pg_catalog.concat_ws(E'\n',
    p_key->>'kty',p_key->>'crv',p_key->>'x',p_key->>'y'),'UTF8'),
   'sha256'),'hex')
$fn$;

-- Once inserted, a pin or audit event cannot be changed by a normal SQL UPDATE
-- or DELETE (a database superuser could still disable triggers; external WORM
-- audit/authority separation remains a required operational security control).
CREATE FUNCTION bl20_issuer_pin_v1_private.deny_history_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO ''
AS $fn$
BEGIN
 RAISE EXCEPTION 'Issuer historical evidence is immutable'
   USING ERRCODE='42501';
END;
$fn$;
CREATE TRIGGER receipt_pin_immutable
 BEFORE UPDATE OR DELETE ON bl20_issuer_pin_v1_private.receipt_pins
 FOR EACH ROW EXECUTE FUNCTION bl20_issuer_pin_v1_private.deny_history_mutation();
CREATE TRIGGER issuer_event_immutable
 BEFORE UPDATE OR DELETE ON bl20_issuer_pin_v1_private.issuer_events
 FOR EACH ROW EXECUTE FUNCTION bl20_issuer_pin_v1_private.deny_history_mutation();

-- Validate an existing pinned review receipt before governance can even
-- stage a non-approval intent. The historical key MUST equal the current
-- reviewed issuer public key and the exact receipt's signed attestation hash.
CREATE FUNCTION bl20_issuer_pin_v1_private.guard_governance_intent_pin()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO ''
AS $fn$
DECLARE
 pin bl20_issuer_pin_v1_private.receipt_pins%ROWTYPE;
 issuer bl20_recovery_v1_private.issuers%ROWTYPE;
 receipt bl20_recovery_v1_private.receipts%ROWTYPE;
BEGIN
 SELECT * INTO pin FROM bl20_issuer_pin_v1_private.receipt_pins
 WHERE challenge_id=NEW.challenge_id AND case_id=NEW.receipt_case_id
 FOR SHARE;
 IF NOT FOUND OR pin.issuer_id<>NEW.issuer_id OR
    pin.issuer_public_key_sha256<>NEW.issuer_key_sha256
 THEN RAISE EXCEPTION 'Governance issuer pin missing or mismatched'
   USING ERRCODE='42501'; END IF;
 SELECT * INTO receipt FROM bl20_recovery_v1_private.receipts
 WHERE challenge_id=NEW.challenge_id AND case_id=NEW.receipt_case_id
 FOR SHARE;
 IF NOT FOUND OR receipt.attestation_sha256<>pin.attestation_sha256
 THEN RAISE EXCEPTION 'Governance attestation pin mismatch'
   USING ERRCODE='42501'; END IF;
 SELECT * INTO issuer FROM bl20_recovery_v1_private.issuers
 WHERE issuer_id=NEW.issuer_id FOR SHARE;
 IF NOT FOUND OR issuer.revoked_at IS NOT NULL OR
    issuer.independently_approved IS NOT TRUE OR
    issuer.public_jwk IS DISTINCT FROM pin.issuer_public_jwk OR
    bl20_issuer_pin_v1_private.key_fingerprint(issuer.public_jwk)
      IS DISTINCT FROM pin.issuer_public_key_sha256
 THEN RAISE EXCEPTION 'Governance issuer changed or revoked'
   USING ERRCODE='42501'; END IF;
 RETURN NEW;
END;
$fn$;
CREATE TRIGGER require_issuer_pin_for_governance
 BEFORE INSERT ON bl20_first_device_v1_private.review_intents
 FOR EACH ROW EXECUTE FUNCTION
  bl20_issuer_pin_v1_private.guard_governance_intent_pin();

-- Ensure every material key rotation, revocation or disable transition is
-- recorded and vetoes all still-pending intents in the SAME DB transaction.
-- A previously revoked issuer cannot be silently unrevoked or reapproved.
CREATE FUNCTION bl20_issuer_pin_v1_private.on_issuer_change()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO ''
AS $fn$
DECLARE
 old_sha text;
 new_sha text;
 change_kind text;
 veto_kind text;
 intent record;
BEGIN
 IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
  RAISE EXCEPTION 'Revoked issuer cannot be automatically reactivated'
   USING ERRCODE='42501'; END IF;
 IF OLD.independently_approved IS FALSE
    AND NEW.independently_approved IS TRUE THEN
  RAISE EXCEPTION 'Issuer reapproval needs separate authority governance'
   USING ERRCODE='42501'; END IF;

 IF OLD.public_jwk IS NOT DISTINCT FROM NEW.public_jwk
   AND OLD.revoked_at IS NOT DISTINCT FROM NEW.revoked_at
   AND OLD.independently_approved IS NOT DISTINCT FROM NEW.independently_approved
 THEN RETURN NEW; END IF;

 old_sha:=bl20_issuer_pin_v1_private.key_fingerprint(OLD.public_jwk);
 new_sha:=bl20_issuer_pin_v1_private.key_fingerprint(NEW.public_jwk);
 IF OLD.revoked_at IS DISTINCT FROM NEW.revoked_at
   AND NEW.revoked_at IS NOT NULL THEN
  change_kind:='issuer_revoked'; veto_kind:='issuer_revoked';
 ELSIF OLD.independently_approved IS TRUE
   AND NEW.independently_approved IS FALSE THEN
  change_kind:='issuer_disabled'; veto_kind:='security_hold';
 ELSE
  change_kind:='key_rotated'; veto_kind:='security_hold';
 END IF;

 INSERT INTO bl20_issuer_pin_v1_private.issuer_events(
   issuer_id,event_kind,old_key_sha256,new_key_sha256)
 VALUES(NEW.issuer_id,change_kind,old_sha,new_sha);

 FOR intent IN
  UPDATE bl20_first_device_v1_private.review_intents
  SET state='governance_vetoed',vetoed_at=clock_timestamp(),
      veto_reason=veto_kind
  WHERE issuer_id=NEW.issuer_id AND state='governance_pending_review_only'
  RETURNING id
 LOOP
  INSERT INTO bl20_first_device_v1_private.audit_events(intent_id,event_kind)
   VALUES(intent.id,'intent_vetoed');
 END LOOP;
 RETURN NEW;
END;
$fn$;
CREATE TRIGGER issuer_key_rotation_and_revocation
 AFTER UPDATE OF public_jwk,revoked_at,independently_approved
 ON bl20_recovery_v1_private.issuers
 FOR EACH ROW EXECUTE FUNCTION bl20_issuer_pin_v1_private.on_issuer_change();

-- The v2 RPC pins the issuer *during* the receipt transaction but did not
-- save an immutable snapshot. In v3, the signed key fingerprint is locked
-- and checked again, v2 consumes the review atomically, and the historical
-- key is recorded in the SAME transaction.
CREATE FUNCTION public.bl20_recovery_v1_review_consume_v3(
 p_user uuid,p_session uuid,p_challenge uuid,p_payload_sha text,
 p_attestation_sha text,p_issuer_public_key_sha text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $fn$
DECLARE
 challenge bl20_recovery_v1_private.challenges%ROWTYPE;
 review_case bl20_recovery_v1_private.cases%ROWTYPE;
 issuer bl20_recovery_v1_private.issuers%ROWTYPE;
 review_receipt bl20_recovery_v1_private.receipts%ROWTYPE;
 result jsonb;
 v_key_sha text;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_challenge IS NULL OR
    p_payload_sha IS NULL OR p_payload_sha !~ '^[a-f0-9]{64}$' OR
    p_attestation_sha IS NULL OR p_attestation_sha !~ '^[a-f0-9]{64}$' OR
    p_issuer_public_key_sha IS NULL OR p_issuer_public_key_sha !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Pinned review rejected' USING ERRCODE='42501'; END IF;

 SELECT * INTO challenge FROM bl20_recovery_v1_private.challenges
 WHERE id=p_challenge AND user_id=p_user AND session_id=p_session
 FOR UPDATE;
 IF NOT FOUND OR challenge.state<>'pending' OR challenge.consumed_at IS NOT NULL
   OR challenge.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'Pinned review rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO review_case FROM bl20_recovery_v1_private.cases
 WHERE challenge_id=challenge.id AND user_id=p_user FOR SHARE;
 IF NOT FOUND OR review_case.state<>'independently_verified'
 THEN RAISE EXCEPTION 'Pinned review rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO issuer FROM bl20_recovery_v1_private.issuers
 WHERE issuer_id=review_case.issuer_id FOR SHARE;
 v_key_sha:=bl20_issuer_pin_v1_private.key_fingerprint(issuer.public_jwk);
 IF NOT FOUND OR issuer.revoked_at IS NOT NULL
  OR issuer.independently_approved IS NOT TRUE
  OR v_key_sha IS DISTINCT FROM p_issuer_public_key_sha
 THEN RAISE EXCEPTION 'Issuer key pin changed' USING ERRCODE='42501'; END IF;

 result:=public.bl20_recovery_v1_review_consume_v2(
  p_user,p_session,p_challenge,
  p_payload_sha,p_attestation_sha,p_issuer_public_key_sha);
 IF result->>'reviewReceiptStored'<>'true'
   OR result->>'deviceApproved'<>'false'
   OR result->>'trustedDevice'<>'false'
   OR result->>'e2eeV2Ready'<>'false'
 THEN RAISE EXCEPTION 'Pinned review rejected' USING ERRCODE='42501'; END IF;

 SELECT * INTO review_receipt FROM bl20_recovery_v1_private.receipts
 WHERE challenge_id=p_challenge AND user_id=p_user FOR SHARE;
 IF NOT FOUND OR review_receipt.case_id<>review_case.id
   OR review_receipt.attestation_sha256<>p_attestation_sha
 THEN RAISE EXCEPTION 'Review receipt changed' USING ERRCODE='42501'; END IF;

 INSERT INTO bl20_issuer_pin_v1_private.receipt_pins
  (challenge_id,case_id,issuer_id,issuer_public_jwk,
   issuer_public_key_sha256,attestation_sha256)
 VALUES(p_challenge,review_case.id,issuer.issuer_id,issuer.public_jwk,
   v_key_sha,p_attestation_sha);
 RETURN pg_catalog.jsonb_build_object(
   'reviewReceiptStored',true,'issuerKeyPinned',true,
   'deviceApproved',false,'trustedDevice',false,'e2eeV2Ready',false);
END;
$fn$;

-- One protected service-role RPC for future reviewed v3 usage.
-- Existing deployed recovery Edge is hard-disabled and calls v2; revocation
-- below ensures it fails closed even if mistakenly re-enabled.
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_consume_v2(
 uuid,uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_consume_v3(
 uuid,uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_recovery_v1_review_consume_v3(
 uuid,uuid,uuid,text,text,text) TO service_role;
REVOKE ALL ON FUNCTION bl20_issuer_pin_v1_private.key_fingerprint(jsonb)
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_issuer_pin_v1_private.deny_history_mutation()
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_issuer_pin_v1_private.guard_governance_intent_pin()
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_issuer_pin_v1_private.on_issuer_change()
 FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
