-- BharathLink Phase 7L — STAGED / EPHEMERAL POSTGRES CI ONLY.
-- NO LIVE DEPLOY. This is a private, non-authorizing, append-only
-- ledger for two separately checked reviewer-signature *digests*.
-- It DOES NOT verify P-256 signatures, grant trust, register devices,
-- consume the real enrollment nonce, or decrypt any chat. Signature
-- verification is an independent Phase7K cryptographic step.
BEGIN;
CREATE SCHEMA bl20_review_ledger_v1_private;
REVOKE ALL ON SCHEMA bl20_review_ledger_v1_private
 FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl20_review_ledger_v1_private.receipts(
 intent_id uuid PRIMARY KEY
   REFERENCES bl20_first_device_v1_private.review_intents(id),
 user_id uuid NOT NULL,
 session_id uuid NOT NULL,
 request_id uuid NOT NULL UNIQUE,
 challenge_id uuid NOT NULL UNIQUE,
 device_id uuid NOT NULL UNIQUE,
 candidate_proof_id uuid NOT NULL UNIQUE,
 issuer_key_sha256 text NOT NULL CHECK(issuer_key_sha256 ~ '^[a-f0-9]{64}$'),
 ecdh_key_sha256 text NOT NULL CHECK(ecdh_key_sha256 ~ '^[a-f0-9]{64}$'),
 signing_key_sha256 text NOT NULL CHECK(signing_key_sha256 ~ '^[a-f0-9]{64}$'),
 reviewed_evidence_sha256 text NOT NULL CHECK(reviewed_evidence_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_a uuid NOT NULL,
 reviewer_b uuid NOT NULL,
 reviewer_a_key_sha256 text NOT NULL CHECK(reviewer_a_key_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_b_key_sha256 text NOT NULL CHECK(reviewer_b_key_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_a_signature_sha256 text NOT NULL CHECK(reviewer_a_signature_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_b_signature_sha256 text NOT NULL CHECK(reviewer_b_signature_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_a_payload_sha256 text NOT NULL CHECK(reviewer_a_payload_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_b_payload_sha256 text NOT NULL CHECK(reviewer_b_payload_sha256 ~ '^[a-f0-9]{64}$'),
 nonce_sha256 text NOT NULL UNIQUE CHECK(nonce_sha256 ~ '^[a-f0-9]{64}$'),
 expires_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 state text NOT NULL DEFAULT 'review_evidence_staged_only'
   CHECK(state='review_evidence_staged_only'),
 CHECK(reviewer_a<>reviewer_b),
 CHECK(reviewer_a_key_sha256<>reviewer_b_key_sha256),
 CHECK(reviewer_a_signature_sha256<>reviewer_b_signature_sha256),
 CHECK(reviewer_a_payload_sha256<>reviewer_b_payload_sha256)
);
CREATE TABLE bl20_review_ledger_v1_private.events(
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 intent_id uuid NOT NULL REFERENCES bl20_review_ledger_v1_private.receipts(intent_id),
 event_kind text NOT NULL CHECK(event_kind='review_evidence_staged_only'),
 occurred_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

ALTER TABLE bl20_review_ledger_v1_private.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl20_review_ledger_v1_private.events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl20_review_ledger_v1_private
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA bl20_review_ledger_v1_private
 FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION bl20_review_ledger_v1_private.deny_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
BEGIN
 RAISE EXCEPTION 'Review evidence ledger is append-only'
  USING ERRCODE='42501';
END;
$body$;
CREATE TRIGGER receipts_immutable
 BEFORE UPDATE OR DELETE ON bl20_review_ledger_v1_private.receipts
 FOR EACH ROW EXECUTE FUNCTION bl20_review_ledger_v1_private.deny_mutation();
CREATE TRIGGER events_immutable
 BEFORE UPDATE OR DELETE ON bl20_review_ledger_v1_private.events
 FOR EACH ROW EXECUTE FUNCTION bl20_review_ledger_v1_private.deny_mutation();

-- OWNER-ONLY, non-authorizing TEST transaction. A caller supplying hex digests
-- is NOT proof that the signatures were checked. DO NOT GRANT an API execute
-- role or use this receipt as device authorization. The source of evidence
-- requires separate trusted server-side key pinning and verification.
CREATE FUNCTION bl20_review_ledger_v1_private.stage_review_evidence(
 p_intent_id uuid,
 p_key_a_sha text,p_key_b_sha text,
 p_signature_a_sha text,p_signature_b_sha text,
 p_payload_a_sha text,p_payload_b_sha text,
 p_nonce_sha text,p_expires_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
DECLARE
 r bl20_first_device_v1_private.review_intents%ROWTYPE;
 now_utc timestamptz := pg_catalog.clock_timestamp();
BEGIN
 IF p_intent_id IS NULL OR
   p_key_a_sha IS NULL OR p_key_a_sha !~ '^[a-f0-9]{64}$' OR
   p_key_b_sha IS NULL OR p_key_b_sha !~ '^[a-f0-9]{64}$' OR
   p_signature_a_sha IS NULL OR p_signature_a_sha !~ '^[a-f0-9]{64}$' OR
   p_signature_b_sha IS NULL OR p_signature_b_sha !~ '^[a-f0-9]{64}$' OR
   p_payload_a_sha IS NULL OR p_payload_a_sha !~ '^[a-f0-9]{64}$' OR
   p_payload_b_sha IS NULL OR p_payload_b_sha !~ '^[a-f0-9]{64}$' OR
   p_nonce_sha IS NULL OR p_nonce_sha !~ '^[a-f0-9]{64}$' OR
   p_key_a_sha=p_key_b_sha OR
   p_signature_a_sha=p_signature_b_sha OR
   p_payload_a_sha=p_payload_b_sha OR
   p_expires_at IS NULL OR p_expires_at<=now_utc OR
   p_expires_at>now_utc+interval '5 minutes'
 THEN RAISE EXCEPTION 'Review evidence receipt rejected' USING ERRCODE='42501'; END IF;

 -- The parent governance intent row is locked before uniqueness checks.
 -- Concurrent attempts on the same case serialize deterministically.
 SELECT * INTO r FROM bl20_first_device_v1_private.review_intents
 WHERE id=p_intent_id FOR UPDATE;
 IF NOT FOUND OR r.state<>'governance_pending_review_only'
   OR r.vetoed_at IS NOT NULL OR r.created_at>now_utc
   OR r.created_at<now_utc-interval '15 minutes'
   OR r.reviewer_a IS NULL OR r.reviewer_b IS NULL
   OR r.reviewer_a=r.reviewer_b OR
   r.reviewer_a=r.user_id OR r.reviewer_b=r.user_id
   OR r.issuer_key_sha256 !~ '^[a-f0-9]{64}$' OR
   r.ecdh_key_sha256 !~ '^[a-f0-9]{64}$' OR
   r.signing_key_sha256 !~ '^[a-f0-9]{64}$' OR
   r.reviewed_evidence_sha256 !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Pending governance intent required' USING ERRCODE='42501'; END IF;

 -- A stale session must never stage new recovery evidence.
 PERFORM 1 FROM auth.sessions s
 WHERE s.id=r.session_id AND s.user_id=r.user_id
   AND (s.not_after IS NULL OR s.not_after>now_utc)
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active account session required' USING ERRCODE='42501'; END IF;

 IF EXISTS(SELECT 1 FROM bl20_review_ledger_v1_private.receipts
           WHERE intent_id=r.id OR request_id=r.request_id
             OR challenge_id=r.challenge_id OR device_id=r.device_id
             OR nonce_sha256=p_nonce_sha)
 THEN RAISE EXCEPTION 'Review evidence replay denied' USING ERRCODE='42501'; END IF;

 INSERT INTO bl20_review_ledger_v1_private.receipts(
  intent_id,user_id,session_id,request_id,challenge_id,device_id,
  candidate_proof_id,issuer_key_sha256,ecdh_key_sha256,signing_key_sha256,
  reviewed_evidence_sha256,reviewer_a,reviewer_b,
  reviewer_a_key_sha256,reviewer_b_key_sha256,
  reviewer_a_signature_sha256,reviewer_b_signature_sha256,
  reviewer_a_payload_sha256,reviewer_b_payload_sha256,
  nonce_sha256,expires_at)
 VALUES(
  r.id,r.user_id,r.session_id,r.request_id,r.challenge_id,r.device_id,
  r.candidate_proof_id,r.issuer_key_sha256,r.ecdh_key_sha256,
  r.signing_key_sha256,r.reviewed_evidence_sha256,
  r.reviewer_a,r.reviewer_b,
  p_key_a_sha,p_key_b_sha,
  p_signature_a_sha,p_signature_b_sha,
  p_payload_a_sha,p_payload_b_sha,
  p_nonce_sha,p_expires_at);
 INSERT INTO bl20_review_ledger_v1_private.events(intent_id,event_kind)
 VALUES(r.id,'review_evidence_staged_only');

 RETURN pg_catalog.jsonb_build_object(
  'reviewEvidenceStagedOnly',true,
  'deviceApproved',false,'trustedDevice',false,
  'e2eeReady',false,'enrollmentCommitted',false,
  'canActivate',false);
END;
$body$;

REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private.deny_mutation()
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private.stage_review_evidence(
 uuid,text,text,text,text,text,text,text,timestamptz)
 FROM PUBLIC,anon,authenticated,service_role;
COMMIT;

-- This is evidence bookkeeping for disposal CI, not the real issuer/approver
-- transaction. An independently audited review-signature verifier is required,
-- and actual first-device trust still requires separately approved governance.
