-- BharathLink Phase 5: STAGED only. Must be loaded after Phase 4 SQL.
-- Pins exact issuer public key through an atomic review receipt transaction.
-- This still NEVER enrolls, approves or trusts any device.
BEGIN;
CREATE FUNCTION public.bl20_recovery_v1_review_consume_v2(
 p_user uuid,p_session uuid,p_challenge uuid,p_payload_sha text,
 p_attestation_sha text,p_issuer_public_key_sha text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $body$
DECLARE
 c bl20_recovery_v1_private.challenges%ROWTYPE;
 r bl20_recovery_v1_private.cases%ROWTYPE;
 i bl20_recovery_v1_private.issuers%ROWTYPE;
 v_actual text;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_challenge IS NULL
    OR p_issuer_public_key_sha IS NULL
    OR p_issuer_public_key_sha !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 -- Lock ordering agrees with legacy commit: challenge -> case -> issuer.
 -- A concurrent issuer revocation/rotation cannot change the verified key
 -- between this check and the inner atomic commit.
 SELECT * INTO c FROM bl20_recovery_v1_private.challenges
  WHERE id=p_challenge AND user_id=p_user AND session_id=p_session
  FOR UPDATE;
 IF NOT FOUND OR c.state<>'pending' OR c.consumed_at IS NOT NULL
    OR c.expires_at<=pg_catalog.clock_timestamp()
 THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM bl20_recovery_v1_private.cases
  WHERE challenge_id=c.id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 SELECT * INTO i FROM bl20_recovery_v1_private.issuers
  WHERE issuer_id=r.issuer_id FOR SHARE;
 IF NOT FOUND OR i.revoked_at IS NOT NULL OR NOT i.independently_approved
 THEN RAISE EXCEPTION 'Recovery rejected' USING ERRCODE='42501'; END IF;
 v_actual:=pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(
      pg_catalog.concat_ws(E'\n',
        i.public_jwk->>'kty',i.public_jwk->>'crv',
        i.public_jwk->>'x',i.public_jwk->>'y'),'UTF8'),
      'sha256'),'hex');
 IF v_actual IS DISTINCT FROM p_issuer_public_key_sha
 THEN RAISE EXCEPTION 'Recovery issuer key changed' USING ERRCODE='42501'; END IF;
 RETURN public.bl20_recovery_v1_review_consume(
   p_user,p_session,p_challenge,p_payload_sha,p_attestation_sha);
END;
$body$;
-- Legacy 5-argument receipt endpoint cannot pin issuer rotation.
-- Keep callable by privileged migration owner ONLY, not by service-role REST.
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_consume(
 uuid,uuid,uuid,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.bl20_recovery_v1_review_consume_v2(
 uuid,uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_recovery_v1_review_consume_v2(
 uuid,uuid,uuid,text,text,text) TO service_role;
COMMIT;
