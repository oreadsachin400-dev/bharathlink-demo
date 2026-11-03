-- BHARATHLINK-20-TEST / Phase 4. STAGED ONLY: NEVER apply to production.
-- This is a review-receipt transaction, NOT a first-device approval transaction.
-- Protected Edge entrypoint stays HARD DISABLED. No trusted issuers are provisioned.
BEGIN;
CREATE SCHEMA IF NOT EXISTS bl20_recovery_v1_private;
REVOKE ALL ON SCHEMA bl20_recovery_v1_private FROM PUBLIC, anon, authenticated;

-- No public issuer-create function. An independently audited authority and
-- two-person governance must be established before any real issuer is inserted.
CREATE TABLE bl20_recovery_v1_private.issuers (
  issuer_id text PRIMARY KEY CHECK(length(issuer_id) BETWEEN 8 AND 128),
  public_jwk jsonb NOT NULL CHECK (
      pg_catalog.jsonb_typeof(public_jwk)='object'
      AND public_jwk->>'kty'='EC'
      AND public_jwk->>'crv'='P-256'
      AND (public_jwk - 'crv' - 'kty' - 'x' - 'y')='{}'::jsonb
      AND COALESCE(public_jwk->>'x','') ~ '^[A-Za-z0-9_-]{43}$'
      AND COALESCE(public_jwk->>'y','') ~ '^[A-Za-z0-9_-]{43}$'),
  independently_approved boolean NOT NULL DEFAULT false,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
CREATE TABLE bl20_recovery_v1_private.challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  user_id uuid NOT NULL REFERENCES auth.users(id),
  session_id uuid NOT NULL REFERENCES auth.sessions(id),
  request_id uuid NOT NULL REFERENCES public.messaging_device_enrollment_requests(request_id),
  candidate_proof_id uuid NOT NULL REFERENCES bl20_candidate_v1_private.proofs(id),
  device_id uuid NOT NULL,
  ecdh_digest text NOT NULL CHECK(ecdh_digest ~ '^[a-f0-9]{64}$'),
  signing_digest text NOT NULL CHECK(signing_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending','review_consumed','expired')),
  consumed_at timestamptz,
  CONSTRAINT one_challenge_per_candidate UNIQUE(candidate_proof_id),
  CHECK(expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK((state='review_consumed')=(consumed_at IS NOT NULL))
);
CREATE INDEX review_challenge_owner_created
 ON bl20_recovery_v1_private.challenges(user_id,created_at DESC);

-- Review cases are inserted only by an audited out-of-band authority, NEVER
-- by an authenticated client or by the challenge RPC. There is no live authority.
CREATE TABLE bl20_recovery_v1_private.cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id uuid NOT NULL UNIQUE REFERENCES bl20_recovery_v1_private.challenges(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  request_id uuid NOT NULL REFERENCES public.messaging_device_enrollment_requests(request_id),
  issuer_id text NOT NULL REFERENCES bl20_recovery_v1_private.issuers(issuer_id),
  evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
  reviewer_a uuid NOT NULL,
  reviewer_b uuid NOT NULL,
  consent_at timestamptz NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'unverified'
    CHECK(state IN ('unverified','independently_verified','revoked')),
  signature_base64url text NOT NULL CHECK(signature_base64url ~ '^[A-Za-z0-9_-]{86}$'),
  CHECK(reviewer_a<>reviewer_b AND reviewer_a<>user_id AND reviewer_b<>user_id),
  CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes')
);
CREATE TABLE bl20_recovery_v1_private.receipts (
  challenge_id uuid PRIMARY KEY REFERENCES bl20_recovery_v1_private.challenges(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  case_id uuid NOT NULL UNIQUE REFERENCES bl20_recovery_v1_private.cases(id),
  payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
  attestation_sha256 text NOT NULL CHECK(attestation_sha256 ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  state text NOT NULL DEFAULT 'review_receipt_only'
    CHECK(state='review_receipt_only')
);
ALTER TABLE bl20_recovery_v1_private.issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_recovery_v1_private.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_recovery_v1_private.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_recovery_v1_private.receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl20_recovery_v1_private FROM PUBLIC,anon,authenticated;

-- Strict synthetic/test-only helper. Full immutable payload is constructed
-- from server-held database rows, never from mobile-provided content.
CREATE FUNCTION public.bl20_recovery_v1_review_payload(
 p_user uuid,p_session uuid,p_request uuid,p_device uuid,
 p_nonce uuid,p_proof uuid,p_ecdh_hash text,p_sign_hash text,
 p_case uuid,p_evidence_hash text,p_reviewer_a uuid,p_reviewer_b uuid,
 p_issued timestamptz,p_expires timestamptz
) RETURNS text LANGUAGE sql STABLE SET search_path TO ''
AS $body$
 SELECT pg_catalog.concat_ws(E'\n',
  'BHARATHLINK_INDEPENDENT_RECOVERY_REVIEW_V1',p_user::text,p_session::text,
  p_request::text,p_device::text,p_nonce::text,p_proof::text,
  p_ecdh_hash,p_sign_hash,p_case::text,p_evidence_hash,
  p_reviewer_a::text,p_reviewer_b::text,
  pg_catalog.to_char(p_issued AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  pg_catalog.to_char(p_expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'REVIEW_ELIGIBLE_ONLY_NO_DEVICE_APPROVAL'
 );
$body$;

-- Service-role-only, gated on a real (not client-supplied) configured issuer.
-- No issuer is bundled with this migration, so real TEST always denies.
CREATE FUNCTION public.bl20_recovery_v1_challenge_start(
 p_user uuid,p_session uuid,p_request uuid,p_proof uuid
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 v_proof bl20_candidate_v1_private.proofs%ROWTYPE;
 v_request public.messaging_device_enrollment_requests%ROWTYPE;
 v_now timestamptz:=pg_catalog.clock_timestamp();
 v_ecdh text; v_sign text;
 v_new bl20_recovery_v1_private.challenges%ROWTYPE;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_request IS NULL OR p_proof IS NULL
 THEN RAISE EXCEPTION 'Recovery unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_user::text,892210));
 IF NOT EXISTS(SELECT 1 FROM auth.sessions s WHERE s.id=p_session
       AND s.user_id=p_user AND (s.not_after IS NULL OR s.not_after>v_now))
 OR NOT EXISTS(SELECT 1 FROM bl20_recovery_v1_private.issuers i
       WHERE i.independently_approved AND i.revoked_at IS NULL)
 THEN RAISE EXCEPTION 'Recovery unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM public.messaging_device_signing_keys k
   JOIN public.messaging_devices d ON d.id=k.device_id AND d.user_id=k.user_id
   WHERE k.user_id=p_user AND k.verified_at IS NOT NULL
   AND k.revoked_at IS NULL AND d.revoked_at IS NULL)
 THEN RAISE EXCEPTION 'Use trusted-device approval, not recovery'
   USING ERRCODE='42501'; END IF;

 SELECT * INTO v_proof FROM bl20_candidate_v1_private.proofs
  WHERE id=p_proof AND user_id=p_user AND state='possession_proven'
    AND consumed_at IS NOT NULL AND created_at>=v_now-interval '15 minutes'
  FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Candidate possession required' USING ERRCODE='42501'; END IF;

 SELECT * INTO v_request FROM public.messaging_device_enrollment_requests
   WHERE request_id=p_request AND user_id=p_user AND proposed_device_id=v_proof.device_id
     AND status='pending' AND consumed_at IS NULL
     AND approved_by_device_id IS NULL AND expires_at>v_now
     AND proposed_public_key_jwk=v_proof.ecdh_public_jwk
     AND proposed_signing_public_key_jwk=v_proof.signing_public_jwk
   FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.messaging_devices
                       WHERE id=v_proof.device_id)
 THEN RAISE EXCEPTION 'Enrollment/key binding invalid' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM bl20_recovery_v1_private.challenges
    WHERE candidate_proof_id=p_proof OR
    (user_id=p_user AND state='pending' AND expires_at>v_now))
 THEN RAISE EXCEPTION 'Recovery challenge already issued' USING ERRCODE='42501'; END IF;
 IF (SELECT pg_catalog.count(*) FROM bl20_recovery_v1_private.challenges
      WHERE user_id=p_user AND created_at>v_now-interval '15 minutes')>=3
 THEN RAISE EXCEPTION 'Recovery rate limit' USING ERRCODE='42501'; END IF;
 v_ecdh:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
     pg_catalog.concat_ws(E'\n','EC','P-256',v_proof.ecdh_public_jwk->>'x',
       v_proof.ecdh_public_jwk->>'y'),'UTF8'),'sha256'),'hex');
 v_sign:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
     pg_catalog.concat_ws(E'\n','EC','P-256',v_proof.signing_public_jwk->>'x',
       v_proof.signing_public_jwk->>'y'),'UTF8'),'sha256'),'hex');
 INSERT INTO bl20_recovery_v1_private.challenges
   (user_id,session_id,request_id,candidate_proof_id,device_id,ecdh_digest,
    signing_digest,created_at,expires_at)
 VALUES(p_user,p_session,p_request,p_proof,v_proof.device_id,v_ecdh,
    v_sign,v_now,v_now+interval '5 minutes') RETURNING * INTO v_new;
 RETURN pg_catalog.jsonb_build_object(
  'challengeId',v_new.id,'nonce',v_new.nonce,'requestId',v_new.request_id,
  'candidateProofId',v_new.candidate_proof_id,'expiresAt',v_new.expires_at,
  'deviceApproved',false,'reviewReady',false);
END;
$body$;

CREATE FUNCTION public.bl20_recovery_v1_review_context(
 p_user uuid,p_session uuid,p_challenge uuid
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 c bl20_recovery_v1_private.challenges%ROWTYPE;
 r bl20_recovery_v1_private.cases%ROWTYPE;
 i bl20_recovery_v1_private.issuers%ROWTYPE;
 v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_challenge IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM auth.sessions s WHERE s.id=p_session AND s.user_id=p_user
      AND (s.not_after IS NULL OR s.not_after>v_now)) THEN RETURN NULL; END IF;
 SELECT * INTO c FROM bl20_recovery_v1_private.challenges
  WHERE id=p_challenge AND user_id=p_user AND session_id=p_session
   AND state='pending' AND consumed_at IS NULL AND expires_at>v_now;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM public.messaging_device_signing_keys k
   JOIN public.messaging_devices d ON d.id=k.device_id AND d.user_id=k.user_id
   WHERE k.user_id=p_user AND k.verified_at IS NOT NULL
   AND k.revoked_at IS NULL AND d.revoked_at IS NULL) THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM bl20_candidate_v1_private.proofs p
    WHERE p.id=c.candidate_proof_id AND p.user_id=c.user_id
      AND p.device_id=c.device_id AND p.state='possession_proven'
      AND p.consumed_at IS NOT NULL
      AND c.ecdh_digest=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
          pg_catalog.concat_ws(E'\n','EC','P-256',p.ecdh_public_jwk->>'x',
            p.ecdh_public_jwk->>'y'),'UTF8'),'sha256'),'hex')
      AND c.signing_digest=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
          pg_catalog.concat_ws(E'\n','EC','P-256',p.signing_public_jwk->>'x',
            p.signing_public_jwk->>'y'),'UTF8'),'sha256'),'hex'))
 THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.messaging_device_enrollment_requests e
   WHERE e.request_id=c.request_id AND e.user_id=p_user
     AND e.proposed_device_id=c.device_id AND e.status='pending'
     AND e.consumed_at IS NULL AND e.approved_by_device_id IS NULL
     AND e.expires_at>v_now
     AND EXISTS(SELECT 1 FROM bl20_candidate_v1_private.proofs p
       WHERE p.id=c.candidate_proof_id AND p.user_id=c.user_id
         AND p.device_id=c.device_id
         AND p.ecdh_public_jwk=e.proposed_public_key_jwk
         AND p.signing_public_jwk=e.proposed_signing_public_key_jwk))
 OR EXISTS(SELECT 1 FROM public.messaging_devices WHERE id=c.device_id)
 THEN RETURN NULL; END IF;
 SELECT * INTO r FROM bl20_recovery_v1_private.cases
  WHERE challenge_id=c.id AND user_id=p_user AND request_id=c.request_id
    AND state='independently_verified' AND issued_at<=v_now
    AND issued_at>=c.created_at AND expires_at>v_now
    AND expires_at<=c.expires_at AND consent_at>=c.created_at
    AND consent_at<=issued_at;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO i FROM bl20_recovery_v1_private.issuers
  WHERE issuer_id=r.issuer_id AND independently_approved
   AND revoked_at IS NULL;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN pg_catalog.jsonb_build_object(
  'payload',public.bl20_recovery_v1_review_payload(c.user_id,c.session_id,
    c.request_id,c.device_id,c.nonce,c.candidate_proof_id,c.ecdh_digest,
    c.signing_digest,r.id,r.evidence_digest,r.reviewer_a,r.reviewer_b,
    r.issued_at,r.expires_at),
  'issuerPublicJwk',i.public_jwk,
  'issuerId',i.issuer_id,
  'signatureBase64Url',r.signature_base64url,
  'challengeId',c.id,
  'deviceTrusted',false,
  'e2eeReady',false
 );
END;
$body$;

-- Called ONLY after a separate server-side issuer P-256 verification.
-- DB locks and independently rechecks all evidence. Positive result is ONLY
-- a receipt, never an INSERT or UPDATE on messaging_devices.
CREATE FUNCTION public.bl20_recovery_v1_review_consume(
 p_user uuid,p_session uuid,p_challenge uuid,
 p_payload_sha text,p_attestation_sha text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 c bl20_recovery_v1_private.challenges%ROWTYPE;
 r bl20_recovery_v1_private.cases%ROWTYPE;
 v_context jsonb;
 v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_challenge IS NULL
   OR p_payload_sha IS NULL OR p_payload_sha !~ '^[a-f0-9]{64}$'
   OR p_attestation_sha IS NULL OR p_attestation_sha !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO c FROM bl20_recovery_v1_private.challenges
  WHERE id=p_challenge AND user_id=p_user AND session_id=p_session FOR UPDATE;
 IF NOT FOUND OR c.state<>'pending' OR c.consumed_at IS NOT NULL
   OR c.expires_at<=v_now THEN
  RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM bl20_recovery_v1_private.cases
  WHERE challenge_id=c.id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM auth.sessions WHERE id=p_session AND user_id=p_user
    AND (not_after IS NULL OR not_after>v_now) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM bl20_candidate_v1_private.proofs
   WHERE id=c.candidate_proof_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM public.messaging_device_enrollment_requests
   WHERE request_id=c.request_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM bl20_recovery_v1_private.issuers
   WHERE issuer_id=r.issuer_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;

 v_context:=public.bl20_recovery_v1_review_context(p_user,p_session,p_challenge);
 IF v_context IS NULL OR
   pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
     v_context->>'payload','UTF8'),'sha256'),'hex') IS DISTINCT FROM p_payload_sha
   OR pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
     v_context->>'signatureBase64Url','UTF8'),'sha256'),'hex')
      IS DISTINCT FROM p_attestation_sha
 THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 UPDATE bl20_recovery_v1_private.challenges
   SET state='review_consumed',consumed_at=v_now
   WHERE id=c.id AND state='pending' AND consumed_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 INSERT INTO bl20_recovery_v1_private.receipts
  (challenge_id,user_id,case_id,payload_sha256,attestation_sha256)
 VALUES(c.id,c.user_id,r.id,p_payload_sha,p_attestation_sha);
 RETURN pg_catalog.jsonb_build_object(
  'reviewReceiptStored',true,'challengeId',c.id,'deviceApproved',false,
  'trustedDevice',false,'e2eeV2Ready',false);
END;
$body$;

-- Critical: automatic PostgreSQL function EXECUTE grant to PUBLIC is revoked.
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_payload(
 uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,uuid,uuid,timestamptz,timestamptz)
 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_challenge_start(uuid,uuid,uuid,uuid)
 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_context(uuid,uuid,uuid)
 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_consume(uuid,uuid,uuid,text,text)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_recovery_v1_challenge_start(uuid,uuid,uuid,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.bl20_recovery_v1_review_context(uuid,uuid,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.bl20_recovery_v1_review_consume(uuid,uuid,uuid,text,text) TO service_role;
COMMIT;
