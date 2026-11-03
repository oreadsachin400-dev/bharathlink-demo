-- BharathLink Phase 7F: STAGED ONLY; do not apply to live TEST or production.
-- Second+ device approval requires fresh cryptographic proof of candidate key
-- possession, exact public key equality, and existing verified approver.
-- DOES NOT authorize independent FIRST DEVICE bootstrap.
-- The old v1 service-role grant is revoked by this migration (fail closed).
BEGIN;
CREATE TABLE IF NOT EXISTS bl20_candidate_v1_private.trusted_approval_links (
  proof_id uuid PRIMARY KEY REFERENCES bl20_candidate_v1_private.proofs(id),
  request_id uuid NOT NULL UNIQUE REFERENCES public.messaging_device_enrollment_requests(request_id),
  device_id uuid NOT NULL UNIQUE REFERENCES public.messaging_devices(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  approved_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
ALTER TABLE bl20_candidate_v1_private.trusted_approval_links ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE bl20_candidate_v1_private.trusted_approval_links
  FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.bl20_commit_device_approval_v2(
 p_user_id uuid,p_request_id uuid,p_approver_device_id uuid,p_candidate_proof_id uuid,
 p_payload_digest text,p_signing_key_digest text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 r public.messaging_device_enrollment_requests%ROWTYPE;
 p bl20_candidate_v1_private.proofs%ROWTYPE;
 result jsonb;
 v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 IF p_user_id IS NULL OR p_request_id IS NULL OR p_approver_device_id IS NULL
   OR p_candidate_proof_id IS NULL OR p_payload_digest IS NULL
   OR p_signing_key_digest IS NULL
   OR p_payload_digest !~ '^[a-f0-9]{64}$'
   OR p_signing_key_digest !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501'; END IF;

 -- Lock ordering is request -> proof, then v1's request -> approver rows.
 SELECT * INTO r FROM public.messaging_device_enrollment_requests
 WHERE request_id=p_request_id AND user_id=p_user_id FOR UPDATE;
 IF NOT FOUND OR r.status<>'pending' OR r.consumed_at IS NOT NULL
    OR r.approved_by_device_id IS NOT NULL OR r.expires_at<=v_now
    OR r.approval_protocol_version IS DISTINCT FROM 2
    OR r.proposed_device_id=p_approver_device_id
    OR r.proposed_signing_public_key_jwk IS NULL
 THEN RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501'; END IF;

 SELECT * INTO p FROM bl20_candidate_v1_private.proofs
 WHERE id=p_candidate_proof_id AND user_id=p_user_id FOR UPDATE;
 IF NOT FOUND OR p.device_id<>r.proposed_device_id
    OR p.state<>'possession_proven' OR p.consumed_at IS NULL
    OR p.created_at>v_now OR p.created_at<v_now-interval '15 minutes'
    OR p.consumed_at<p.created_at OR p.consumed_at>v_now
    OR p.consumed_at<r.created_at-interval '15 minutes'
    OR p.ecdh_public_jwk IS DISTINCT FROM r.proposed_public_key_jwk
    OR p.signing_public_jwk IS DISTINCT FROM r.proposed_signing_public_key_jwk
 THEN RAISE EXCEPTION 'Candidate possession/key binding required'
     USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM bl20_candidate_v1_private.trusted_approval_links
           WHERE proof_id=p.id OR request_id=r.request_id
              OR device_id=r.proposed_device_id)
 THEN RAISE EXCEPTION 'Candidate possession already used' USING ERRCODE='42501'; END IF;

 -- v1 still checks verified, not-revoked *existing* approver's ECDSA
 -- signing key digest, server-selected approval payload hash and locks.
 -- The protected Edge MUST independently verify the approver's P-256
 -- signature before invoking this service-only RPC. SQL alone does not.
 result:=public.bl20_commit_device_approval(
   p_user_id,p_request_id,p_approver_device_id,
   p_payload_digest,p_signing_key_digest);
 IF result->>'approved' IS DISTINCT FROM 'true'
    OR result->>'deviceId' IS DISTINCT FROM r.proposed_device_id::text
 THEN RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501'; END IF;

 -- Same transaction as device insert; unique proof enforces single-use.
 INSERT INTO bl20_candidate_v1_private.trusted_approval_links
  (proof_id,request_id,device_id,user_id)
 VALUES(p.id,r.request_id,r.proposed_device_id,r.user_id);
 RETURN pg_catalog.jsonb_build_object(
  'approved',true,'deviceId',r.proposed_device_id::text,
  'requestId',r.request_id::text,'candidateProofBound',true);
END;
$body$;

-- The deployed v1 Edge handler is still hard-disabled and calls v1. If its
-- gate were accidentally toggled, this REVOKE makes that old path deny.
REVOKE ALL ON FUNCTION public.bl20_commit_device_approval(
 uuid,uuid,uuid,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.bl20_commit_device_approval_v2(
 uuid,uuid,uuid,uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_commit_device_approval_v2(
 uuid,uuid,uuid,uuid,text,text) TO service_role;
COMMIT;
