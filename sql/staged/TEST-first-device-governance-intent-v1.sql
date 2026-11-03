-- BHARATHLINK Phase 7G — DISPOSABLE CI/STAGED DESIGN ONLY.
-- First-device review governance INTENT, NEVER an authorization or enrollment.
-- Apply ONLY after Phase 4+5 review schema in disposable tests. No live deploy.
BEGIN;
CREATE SCHEMA bl20_first_device_v1_private;
REVOKE ALL ON SCHEMA bl20_first_device_v1_private
  FROM PUBLIC,anon,authenticated,service_role;

-- Explicitly no "approved" state or trusted device fields in this table.
CREATE TABLE bl20_first_device_v1_private.review_intents(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id uuid NOT NULL UNIQUE
    REFERENCES bl20_recovery_v1_private.challenges(id),
  receipt_case_id uuid NOT NULL UNIQUE
    REFERENCES bl20_recovery_v1_private.cases(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  session_id uuid NOT NULL REFERENCES auth.sessions(id),
  request_id uuid NOT NULL UNIQUE
    REFERENCES public.messaging_device_enrollment_requests(request_id),
  device_id uuid NOT NULL UNIQUE,
  candidate_proof_id uuid NOT NULL UNIQUE
    REFERENCES bl20_candidate_v1_private.proofs(id),
  issuer_id text NOT NULL
    REFERENCES bl20_recovery_v1_private.issuers(issuer_id),
  issuer_key_sha256 text NOT NULL
    CHECK(issuer_key_sha256 ~ '^[a-f0-9]{64}$'),
  ecdh_key_sha256 text NOT NULL
    CHECK(ecdh_key_sha256 ~ '^[a-f0-9]{64}$'),
  signing_key_sha256 text NOT NULL
    CHECK(signing_key_sha256 ~ '^[a-f0-9]{64}$'),
  reviewed_evidence_sha256 text NOT NULL
    CHECK(reviewed_evidence_sha256 ~ '^[a-f0-9]{64}$'),
  reviewer_a uuid NOT NULL,
  reviewer_b uuid NOT NULL,
  consent_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  state text NOT NULL DEFAULT 'governance_pending_review_only'
    CHECK(state IN ('governance_pending_review_only','governance_vetoed')),
  vetoed_at timestamptz,
  veto_reason text CHECK(veto_reason IN (
    'consent_withdrawn','issuer_revoked','review_disputed','security_hold')),
  CHECK(reviewer_a<>reviewer_b AND reviewer_a<>user_id AND reviewer_b<>user_id),
  CHECK(
    (state='governance_pending_review_only' AND vetoed_at IS NULL AND veto_reason IS NULL)
    OR (state='governance_vetoed' AND vetoed_at IS NOT NULL AND veto_reason IS NOT NULL))
);
CREATE TABLE bl20_first_device_v1_private.audit_events(
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  intent_id uuid NOT NULL REFERENCES bl20_first_device_v1_private.review_intents(id),
  event_kind text NOT NULL CHECK(event_kind IN ('intent_staged','intent_vetoed')),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE bl20_first_device_v1_private.review_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_first_device_v1_private.audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl20_first_device_v1_private
  FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA bl20_first_device_v1_private
  FROM PUBLIC,anon,authenticated,service_role;

-- No service-role or Data API entrypoint: callable ONLY by a privileged
-- migration owner in a disposable database. This function can NOT approve.
CREATE FUNCTION bl20_first_device_v1_private.stage_review_intent(
  p_user uuid,p_session uuid,p_challenge uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
DECLARE
  c bl20_recovery_v1_private.challenges%ROWTYPE;
  rr bl20_recovery_v1_private.receipts%ROWTYPE;
  rc bl20_recovery_v1_private.cases%ROWTYPE;
  issuer bl20_recovery_v1_private.issuers%ROWTYPE;
  candidate bl20_candidate_v1_private.proofs%ROWTYPE;
  request public.messaging_device_enrollment_requests%ROWTYPE;
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_payload text;
  v_issuer_sha text;
  v_ecdh_sha text;
  v_sign_sha text;
  v_intent uuid;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_challenge IS NULL
 THEN RAISE EXCEPTION 'Governance unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(p_user::text,907013));

 PERFORM 1 FROM auth.sessions s
 WHERE s.id=p_session AND s.user_id=p_user
   AND (s.not_after IS NULL OR s.not_after>v_now)
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active session required' USING ERRCODE='42501'; END IF;

 SELECT * INTO c FROM bl20_recovery_v1_private.challenges
 WHERE id=p_challenge AND user_id=p_user AND session_id=p_session FOR SHARE;
 IF NOT FOUND OR c.state<>'review_consumed' OR c.consumed_at IS NULL
    OR c.created_at>v_now OR c.expires_at<=v_now
 THEN RAISE EXCEPTION 'Consumed review challenge required' USING ERRCODE='42501'; END IF;

 SELECT * INTO rr FROM bl20_recovery_v1_private.receipts
 WHERE challenge_id=c.id AND user_id=p_user AND state='review_receipt_only'
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Signed review receipt required' USING ERRCODE='42501'; END IF;

 SELECT * INTO rc FROM bl20_recovery_v1_private.cases
 WHERE id=rr.case_id AND challenge_id=c.id AND user_id=p_user
   AND request_id=c.request_id FOR SHARE;
 IF NOT FOUND OR rc.state<>'independently_verified'
    OR rc.issued_at<v_now-interval '5 minutes'
    OR rc.issued_at>v_now OR rc.issued_at<c.created_at
    OR rc.expires_at<=v_now OR rc.expires_at>c.expires_at
    OR rc.consent_at<c.created_at OR rc.consent_at>rc.issued_at
    OR rc.reviewer_a=rc.reviewer_b OR rc.reviewer_a=p_user OR rc.reviewer_b=p_user
 THEN RAISE EXCEPTION 'Independent review and consent required' USING ERRCODE='42501'; END IF;

 SELECT * INTO issuer FROM bl20_recovery_v1_private.issuers
 WHERE issuer_id=rc.issuer_id FOR SHARE;
 IF NOT FOUND OR NOT issuer.independently_approved OR issuer.revoked_at IS NOT NULL
 THEN RAISE EXCEPTION 'Independent issuer unavailable' USING ERRCODE='42501'; END IF;

 SELECT * INTO candidate FROM bl20_candidate_v1_private.proofs
 WHERE id=c.candidate_proof_id AND user_id=p_user AND device_id=c.device_id
 FOR SHARE;
 IF NOT FOUND OR candidate.state<>'possession_proven'
    OR candidate.consumed_at IS NULL OR candidate.created_at>v_now
    OR candidate.created_at<v_now-interval '15 minutes'
    OR candidate.consumed_at>v_now OR candidate.consumed_at<candidate.created_at
 THEN RAISE EXCEPTION 'Candidate possession required' USING ERRCODE='42501'; END IF;

 SELECT * INTO request FROM public.messaging_device_enrollment_requests
 WHERE request_id=c.request_id AND user_id=p_user
   AND proposed_device_id=c.device_id FOR SHARE;
 IF NOT FOUND OR request.status<>'pending' OR request.consumed_at IS NOT NULL
    OR request.approved_by_device_id IS NOT NULL OR request.expires_at<=v_now
    OR request.approval_protocol_version IS DISTINCT FROM 3
    OR request.proposed_public_key_jwk IS DISTINCT FROM candidate.ecdh_public_jwk
    OR request.proposed_signing_public_key_jwk IS DISTINCT FROM candidate.signing_public_jwk
 THEN RAISE EXCEPTION 'Request or proposed keys not eligible' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM public.messaging_devices WHERE id=c.device_id)
 OR EXISTS(SELECT 1 FROM public.messaging_device_signing_keys k
    JOIN public.messaging_devices d ON d.id=k.device_id AND d.user_id=k.user_id
    WHERE k.user_id=p_user AND k.verified_at IS NOT NULL
      AND k.revoked_at IS NULL AND d.revoked_at IS NULL)
 THEN RAISE EXCEPTION 'Not a first untrusted device' USING ERRCODE='42501'; END IF;

 v_ecdh_sha:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
   pg_catalog.concat_ws(E'\n','EC','P-256',candidate.ecdh_public_jwk->>'x',
   candidate.ecdh_public_jwk->>'y'),'UTF8'),'sha256'),'hex');
 v_sign_sha:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
   pg_catalog.concat_ws(E'\n','EC','P-256',candidate.signing_public_jwk->>'x',
   candidate.signing_public_jwk->>'y'),'UTF8'),'sha256'),'hex');
 IF v_ecdh_sha<>c.ecdh_digest OR v_sign_sha<>c.signing_digest
 THEN RAISE EXCEPTION 'Candidate key digest mismatch' USING ERRCODE='42501'; END IF;

 v_payload:=public.bl20_recovery_v1_review_payload(
   c.user_id,c.session_id,c.request_id,c.device_id,c.nonce,c.candidate_proof_id,
   c.ecdh_digest,c.signing_digest,rc.id,rc.evidence_digest,
   rc.reviewer_a,rc.reviewer_b,rc.issued_at,rc.expires_at);
 IF pg_catalog.encode(extensions.digest(pg_catalog.convert_to(v_payload,'UTF8'),
   'sha256'),'hex') IS DISTINCT FROM rr.payload_sha256
 OR pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
   rc.signature_base64url,'UTF8'),'sha256'),'hex') IS DISTINCT FROM rr.attestation_sha256
 THEN RAISE EXCEPTION 'Review receipt binding mismatch' USING ERRCODE='42501'; END IF;
 v_issuer_sha:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
   pg_catalog.concat_ws(E'\n',issuer.public_jwk->>'kty',issuer.public_jwk->>'crv',
   issuer.public_jwk->>'x',issuer.public_jwk->>'y'),'UTF8'),'sha256'),'hex');

 INSERT INTO bl20_first_device_v1_private.review_intents
   (challenge_id,receipt_case_id,user_id,session_id,request_id,device_id,
    candidate_proof_id,issuer_id,issuer_key_sha256,ecdh_key_sha256,
    signing_key_sha256,reviewed_evidence_sha256,reviewer_a,reviewer_b,consent_at)
 VALUES
   (c.id,rc.id,p_user,p_session,c.request_id,c.device_id,c.candidate_proof_id,
    issuer.issuer_id,v_issuer_sha,v_ecdh_sha,v_sign_sha,rc.evidence_digest,
    rc.reviewer_a,rc.reviewer_b,rc.consent_at)
 RETURNING id INTO v_intent;
 INSERT INTO bl20_first_device_v1_private.audit_events(intent_id,event_kind)
 VALUES(v_intent,'intent_staged');
 RETURN pg_catalog.jsonb_build_object(
   'intentId',v_intent::text,'governancePending',true,
   'independentAuthorityVerified',false,'deviceApproved',false,
   'trustedDevice',false,'e2eeV2Ready',false);
END;
$body$;

CREATE FUNCTION bl20_first_device_v1_private.veto_review_intent(
  p_intent uuid,p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
DECLARE v_intent uuid;
BEGIN
 IF p_intent IS NULL OR p_reason IS NULL OR p_reason NOT IN (
   'consent_withdrawn','issuer_revoked','review_disputed','security_hold')
 THEN RAISE EXCEPTION 'Governance veto denied' USING ERRCODE='42501'; END IF;
 UPDATE bl20_first_device_v1_private.review_intents
 SET state='governance_vetoed',vetoed_at=pg_catalog.clock_timestamp(),
     veto_reason=p_reason
 WHERE id=p_intent AND state='governance_pending_review_only'
 RETURNING id INTO v_intent;
 IF NOT FOUND THEN RAISE EXCEPTION 'Governance veto denied' USING ERRCODE='42501'; END IF;
 INSERT INTO bl20_first_device_v1_private.audit_events(intent_id,event_kind)
 VALUES(v_intent,'intent_vetoed');
 RETURN pg_catalog.jsonb_build_object(
   'vetoRecorded',true,'deviceApproved',false,'trustedDevice',false,
   'e2eeV2Ready',false);
END;
$body$;

-- No public, logged-in, or service-role ability to stage/veto an intent.
REVOKE ALL ON FUNCTION bl20_first_device_v1_private.stage_review_intent(uuid,uuid,uuid)
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_first_device_v1_private.veto_review_intent(uuid,text)
 FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
