-- BharathLink-20-TEST only. Candidate proof of possession, NOT device approval.
-- Server authentication occurs in a separately gated Edge Function.
-- No existing messaging_devices, signing keys, verification flags or RLS policies altered.
BEGIN;
CREATE SCHEMA IF NOT EXISTS bl20_candidate_v1_private;
REVOKE ALL ON SCHEMA bl20_candidate_v1_private FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS bl20_candidate_v1_private.proofs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL,
  ecdh_public_jwk jsonb NOT NULL,
  signing_public_jwk jsonb NOT NULL,
  challenge_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '5 minutes'),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','possession_proven','expired')),
  consumed_at timestamptz,
  CHECK (expires_at>created_at AND expires_at<=created_at + interval '5 minutes'),
  CHECK (state <> 'possession_proven' OR consumed_at IS NOT NULL)
);
ALTER TABLE bl20_candidate_v1_private.proofs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl20_candidate_v1_private.proofs FROM PUBLIC, anon, authenticated;
CREATE INDEX IF NOT EXISTS bl20_candidate_user_created
  ON bl20_candidate_v1_private.proofs (user_id,created_at DESC);

CREATE OR REPLACE FUNCTION public.bl20_candidate_proof_payload(
  p_id uuid,p_user_id uuid,p_device_id uuid,p_challenge_id uuid,
  p_expires_at timestamptz,p_ecdh_public_jwk jsonb,p_signing_public_jwk jsonb
) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path TO ''
AS $body$
 SELECT pg_catalog.concat_ws(E'\n',
  'BHARATHLINK_CANDIDATE_POSSESSION_V1',
  p_user_id::text,p_id::text,p_device_id::text,p_challenge_id::text,
  pg_catalog.to_char(p_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  pg_catalog.encode(extensions.digest(pg_catalog.convert_to(p_ecdh_public_jwk::text,'UTF8'),'sha256'),'hex'),
  pg_catalog.encode(extensions.digest(pg_catalog.convert_to(p_signing_public_jwk::text,'UTF8'),'sha256'),'hex')
 )
$body$;

CREATE OR REPLACE FUNCTION public.bl20_candidate_proof_start(
  p_user_id uuid,p_device_id uuid,p_ecdh_public_jwk jsonb,p_signing_public_jwk jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 r bl20_candidate_v1_private.proofs%ROWTYPE;
 v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
 IF p_user_id IS NULL OR p_device_id IS NULL
   OR p_ecdh_public_jwk IS NULL OR p_signing_public_jwk IS NULL
   OR NOT EXISTS (SELECT 1 FROM auth.users WHERE id=p_user_id)
 THEN RAISE EXCEPTION 'Candidate proof denied' USING ERRCODE='42501'; END IF;

 -- Accept exactly the four public P-256 JWK members. No private key material.
 IF pg_catalog.jsonb_typeof(p_ecdh_public_jwk)<>'object'
    OR pg_catalog.jsonb_typeof(p_signing_public_jwk)<>'object'
    OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_ecdh_public_jwk))<>4
    OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_signing_public_jwk))<>4
    OR p_ecdh_public_jwk->>'kty' IS DISTINCT FROM 'EC'
    OR p_ecdh_public_jwk->>'crv' IS DISTINCT FROM 'P-256'
    OR p_signing_public_jwk->>'kty' IS DISTINCT FROM 'EC'
    OR p_signing_public_jwk->>'crv' IS DISTINCT FROM 'P-256'
    OR COALESCE(p_ecdh_public_jwk->>'x','') !~ '^[A-Za-z0-9_-]{43}$'
    OR COALESCE(p_ecdh_public_jwk->>'y','') !~ '^[A-Za-z0-9_-]{43}$'
    OR COALESCE(p_signing_public_jwk->>'x','') !~ '^[A-Za-z0-9_-]{43}$'
    OR COALESCE(p_signing_public_jwk->>'y','') !~ '^[A-Za-z0-9_-]{43}$'
 THEN RAISE EXCEPTION 'Invalid public keys' USING ERRCODE='22023'; END IF;

 -- Serialize requests per authenticated owner, fail closed on duplicate/replay.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_user_id::text,483010));
 IF EXISTS (SELECT 1 FROM public.messaging_devices WHERE id=p_device_id)
 THEN RAISE EXCEPTION 'Candidate device already exists' USING ERRCODE='23505'; END IF;
 IF EXISTS (SELECT 1 FROM bl20_candidate_v1_private.proofs
            WHERE device_id=p_device_id AND user_id<>p_user_id)
 THEN RAISE EXCEPTION 'Device binding conflict' USING ERRCODE='42501'; END IF;
 IF EXISTS (SELECT 1 FROM bl20_candidate_v1_private.proofs
            WHERE user_id=p_user_id AND device_id=p_device_id
              AND state='pending' AND expires_at>v_now)
 THEN RAISE EXCEPTION 'Candidate request already pending' USING ERRCODE='23505'; END IF;
 IF (SELECT count(*) FROM bl20_candidate_v1_private.proofs
     WHERE user_id=p_user_id AND created_at>v_now-interval '15 minutes') >= 5
 THEN RAISE EXCEPTION 'Rate limit' USING ERRCODE='42501'; END IF;
 INSERT INTO bl20_candidate_v1_private.proofs
  (user_id,device_id,ecdh_public_jwk,signing_public_jwk,created_at,expires_at)
 VALUES (p_user_id,p_device_id,p_ecdh_public_jwk,p_signing_public_jwk,
   v_now,v_now+interval '5 minutes')
 RETURNING * INTO r;

 RETURN pg_catalog.jsonb_build_object(
   'proofId',r.id::text,'deviceId',r.device_id::text,
   'userId',r.user_id::text,'expiresAt',
   pg_catalog.to_char(r.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   'signingPublicJwk',r.signing_public_jwk,
   'payload',public.bl20_candidate_proof_payload(
     r.id,r.user_id,r.device_id,r.challenge_id,r.expires_at,r.ecdh_public_jwk,r.signing_public_jwk),
   'serverApproved',false
 );
END;
$body$;

CREATE OR REPLACE FUNCTION public.bl20_candidate_proof_context(
  p_user_id uuid,p_proof_id uuid
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE r bl20_candidate_v1_private.proofs%ROWTYPE;
BEGIN
 SELECT * INTO r FROM bl20_candidate_v1_private.proofs
 WHERE id=p_proof_id AND user_id=p_user_id AND state='pending'
   AND expires_at>pg_catalog.clock_timestamp() AND consumed_at IS NULL;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN pg_catalog.jsonb_build_object(
   'proofId',r.id::text,'userId',r.user_id::text,
   'deviceId',r.device_id::text,'signingPublicJwk',r.signing_public_jwk,
   'payload',public.bl20_candidate_proof_payload(
     r.id,r.user_id,r.device_id,r.challenge_id,r.expires_at,r.ecdh_public_jwk,r.signing_public_jwk)
 );
END;
$body$;

CREATE OR REPLACE FUNCTION public.bl20_candidate_proof_finish(
 p_user_id uuid,p_proof_id uuid,p_payload_hash text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE r bl20_candidate_v1_private.proofs%ROWTYPE;
 v_payload text;
BEGIN
 IF p_user_id IS NULL OR p_proof_id IS NULL OR p_payload_hash IS NULL
   OR p_payload_hash !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Candidate proof denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM bl20_candidate_v1_private.proofs
   WHERE id=p_proof_id AND user_id=p_user_id FOR UPDATE;
 IF NOT FOUND OR r.state<>'pending' OR r.consumed_at IS NOT NULL
    OR r.expires_at<=pg_catalog.clock_timestamp()
 THEN RAISE EXCEPTION 'Candidate proof denied' USING ERRCODE='42501'; END IF;
 v_payload:=public.bl20_candidate_proof_payload(
   r.id,r.user_id,r.device_id,r.challenge_id,r.expires_at,r.ecdh_public_jwk,r.signing_public_jwk);
 IF pg_catalog.encode(extensions.digest(pg_catalog.convert_to(v_payload,'UTF8'),'sha256'),'hex')
     IS DISTINCT FROM p_payload_hash
 THEN RAISE EXCEPTION 'Candidate proof denied' USING ERRCODE='42501'; END IF;
 UPDATE bl20_candidate_v1_private.proofs SET
   state='possession_proven',consumed_at=pg_catalog.clock_timestamp()
 WHERE id=p_proof_id AND state='pending';
 RETURN pg_catalog.jsonb_build_object(
   'proofId',r.id::text,'deviceId',r.device_id::text,
   'possessionProven',true,'serverApproved',false,
   'trustedDevice',false,'e2eeV2Ready',false
 );
END;
$body$;

REVOKE ALL ON FUNCTION public.bl20_candidate_proof_payload(uuid,uuid,uuid,uuid,timestamptz,jsonb,jsonb)
  FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)
  FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_candidate_proof_context(uuid,uuid)
  FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_candidate_proof_finish(uuid,uuid,text)
  FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_candidate_proof_start(uuid,uuid,jsonb,jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.bl20_candidate_proof_context(uuid,uuid)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.bl20_candidate_proof_finish(uuid,uuid,text)
  TO service_role;
COMMIT;
