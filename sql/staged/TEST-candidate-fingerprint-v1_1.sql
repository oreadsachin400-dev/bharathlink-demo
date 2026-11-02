-- BharathLink-20-TEST candidate protocol v1.1:
-- Standardise fingerprint bytes across Android Keystore, JavaScript and PostgreSQL.
-- Fingerprint = SHA256(UTF8("EC\nP-256\n<x43>\n<y43>")).
-- Never change an active in-flight protocol without version negotiation.
-- TEST candidate edge remains hard-disabled, and candidate table has zero rows.
BEGIN;
CREATE OR REPLACE FUNCTION public.bl20_candidate_proof_payload(
  p_id uuid,p_user_id uuid,p_device_id uuid,p_challenge_id uuid,
  p_expires_at timestamptz,p_ecdh_public_jwk jsonb,p_signing_public_jwk jsonb
) RETURNS text
LANGUAGE sql STABLE SET search_path TO ''
AS $body$
 SELECT pg_catalog.concat_ws(E'\n',
  'BHARATHLINK_CANDIDATE_POSSESSION_V1',
  p_user_id::text,p_id::text,p_device_id::text,p_challenge_id::text,
  pg_catalog.to_char(p_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
      pg_catalog.concat_ws(E'\n',
        p_ecdh_public_jwk->>'kty',p_ecdh_public_jwk->>'crv',
        p_ecdh_public_jwk->>'x',p_ecdh_public_jwk->>'y'),'UTF8'),'sha256'),'hex'),
  pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
      pg_catalog.concat_ws(E'\n',
        p_signing_public_jwk->>'kty',p_signing_public_jwk->>'crv',
        p_signing_public_jwk->>'x',p_signing_public_jwk->>'y'),'UTF8'),'sha256'),'hex')
 )
$body$;
REVOKE ALL ON FUNCTION public.bl20_candidate_proof_payload(
 uuid,uuid,uuid,uuid,timestamptz,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
COMMIT;
