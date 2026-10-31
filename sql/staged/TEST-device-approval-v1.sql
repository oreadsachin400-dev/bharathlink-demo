-- BharathLink-20-TEST: STAGED ONLY, NOT AUTOMATICALLY APPLIED.
-- Service-role RPCs for a previously verified trusted device to approve a new one.
-- No first-device bootstrap, no approval without verified signing keys.
-- Never weaken messaging_devices authenticated INSERT RLS.
BEGIN;

CREATE OR REPLACE FUNCTION public.bl20_device_approval_context(
  p_user_id uuid, p_request_id uuid, p_approver_device_id uuid
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO ''
AS $body$
DECLARE
  r public.messaging_device_enrollment_requests%ROWTYPE;
  k public.messaging_device_signing_keys%ROWTYPE;
  v_payload text;
  v_ecd_hash text;
  v_new_sign_hash text;
  v_approver_key_hash text;
BEGIN
  IF p_user_id IS NULL OR p_request_id IS NULL OR p_approver_device_id IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT * INTO r
    FROM public.messaging_device_enrollment_requests
    WHERE request_id=p_request_id AND user_id=p_user_id
      AND status='pending' AND expires_at>pg_catalog.clock_timestamp()
      AND consumed_at IS NULL AND approved_by_device_id IS NULL
      AND proposed_signing_public_key_jwk IS NOT NULL;
  IF NOT FOUND OR r.proposed_device_id=p_approver_device_id THEN RETURN NULL; END IF;
  IF EXISTS (SELECT 1 FROM public.messaging_devices WHERE id=r.proposed_device_id) THEN RETURN NULL; END IF;

  SELECT sk.* INTO k
  FROM public.messaging_device_signing_keys sk
  JOIN public.messaging_devices d ON d.id=sk.device_id AND d.user_id=sk.user_id
  WHERE sk.device_id=p_approver_device_id AND sk.user_id=p_user_id
    AND d.revoked_at IS NULL
    AND sk.revoked_at IS NULL
    AND sk.verified_at IS NOT NULL
    AND sk.verified_at<=r.created_at
    AND sk.verification_method IN ('trusted_device_signature','audited_recovery');
  IF NOT FOUND THEN RETURN NULL; END IF;

  v_ecd_hash:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(r.proposed_public_key_jwk::text,'UTF8'),'sha256'),'hex');
  v_new_sign_hash:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(r.proposed_signing_public_key_jwk::text,'UTF8'),'sha256'),'hex');
  v_approver_key_hash:=pg_catalog.encode(extensions.digest(pg_catalog.convert_to(k.signing_public_key_jwk::text,'UTF8'),'sha256'),'hex');

  v_payload:=pg_catalog.concat_ws(E'\n',
    'BHARATHLINK_DEVICE_ENROLLMENT_APPROVAL_V1',
    p_user_id::text, r.request_id::text, r.challenge_id::text,
    p_approver_device_id::text, r.proposed_device_id::text,
    pg_catalog.to_char(r.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    v_ecd_hash,v_new_sign_hash
  );
  RETURN pg_catalog.jsonb_build_object(
    'userId',p_user_id::text,
    'requestId',r.request_id::text,
    'approverDeviceId',p_approver_device_id::text,
    'signingPublicJwk',k.signing_public_key_jwk,
    'signingKeyDigest',v_approver_key_hash,
    'payload',v_payload
  );
END;
$body$;

CREATE OR REPLACE FUNCTION public.bl20_commit_device_approval(
  p_user_id uuid,
  p_request_id uuid,
  p_approver_device_id uuid,
  p_payload_digest text,
  p_signing_key_digest text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path TO ''
AS $body$
DECLARE
  r public.messaging_device_enrollment_requests%ROWTYPE;
  v_context jsonb;
  v_current_digest text;
  v_device_id uuid;
BEGIN
  IF p_user_id IS NULL OR p_request_id IS NULL OR p_approver_device_id IS NULL
     OR p_payload_digest !~ '^[a-f0-9]{64}$'
     OR p_signing_key_digest !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501';
  END IF;

  -- Serialize simultaneous approvals and prevent replay.
  SELECT * INTO r FROM public.messaging_device_enrollment_requests
   WHERE request_id=p_request_id AND user_id=p_user_id FOR UPDATE;
  IF NOT FOUND OR r.status<>'pending' OR r.expires_at<=pg_catalog.clock_timestamp()
     OR r.consumed_at IS NOT NULL OR r.approved_by_device_id IS NOT NULL
     OR r.proposed_device_id=p_approver_device_id
     OR r.proposed_signing_public_key_jwk IS NULL THEN
    RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501';
  END IF;

  -- Lock the existing trusted approver and its verified signing key.
  PERFORM 1 FROM public.messaging_devices
    WHERE id=p_approver_device_id AND user_id=p_user_id AND revoked_at IS NULL
    FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM public.messaging_device_signing_keys
    WHERE device_id=p_approver_device_id AND user_id=p_user_id
      AND revoked_at IS NULL AND verified_at IS NOT NULL
      AND verified_at<=r.created_at
      AND verification_method IN ('trusted_device_signature','audited_recovery')
    FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501'; END IF;

  -- Edge has already verified ECDSA-P256 over the server-selected payload.
  -- The DB independently reconstitutes and pins the exact request + signer key.
  v_context:=public.bl20_device_approval_context(
    p_user_id,p_request_id,p_approver_device_id);
  IF v_context IS NULL OR v_context->>'signingKeyDigest'<>p_signing_key_digest
     OR pg_catalog.encode(
        extensions.digest(pg_catalog.convert_to(v_context->>'payload','UTF8'),'sha256'),
        'hex')<>p_payload_digest THEN
    RAISE EXCEPTION 'Approval rejected' USING ERRCODE='42501';
  END IF;

  INSERT INTO public.messaging_devices
    (id,user_id,public_key_jwk,key_algorithm,device_label)
  VALUES
    (r.proposed_device_id,r.user_id,r.proposed_public_key_jwk,
     'ECDH-P256',r.device_label)
  RETURNING id INTO v_device_id;

  INSERT INTO public.messaging_device_signing_keys
    (device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
  VALUES
    (v_device_id,r.user_id,r.proposed_signing_public_key_jwk,
     pg_catalog.clock_timestamp(),'trusted_device_signature');

  UPDATE public.messaging_device_enrollment_requests
    SET status='approved', approved_by_device_id=p_approver_device_id,
        consumed_at=pg_catalog.clock_timestamp()
  WHERE request_id=p_request_id AND user_id=p_user_id AND status='pending';

  RETURN pg_catalog.jsonb_build_object(
    'approved',true,'requestId',r.request_id::text,
    'deviceId',v_device_id::text
  );
END;
$body$;

-- Explicitly remove inherited PUBLIC/anon/authenticated EXECUTE privileges;
-- service_role is the only caller, via the protected Edge Function.
REVOKE ALL ON FUNCTION public.bl20_device_approval_context(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.bl20_commit_device_approval(uuid,uuid,uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bl20_device_approval_context(uuid,uuid,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.bl20_commit_device_approval(uuid,uuid,uuid,text,text) TO service_role;
COMMIT;

-- Deployment requirements:
-- - Apply to BharathLink-20-TEST project only after review and test suite pass.
-- - Keep approval Edge Function disabled by default until independently
--   attested signing key is registered (currently 0 eligible signing keys).
-- - Recheck permissions, owner, RLS, and negative cases before enablement.
-- - Never allow a client to call either privileged RPC directly.
