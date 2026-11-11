-- REVIEW-ONLY metadata inbox. Disposable PostgreSQL 16 tests ONLY.
-- NOT A MIGRATION; DO NOT APPLY TO ACTIVE BHARATHLINK TEST OR PROD.
--
-- Private, key-free recipient index survives View Once consumption, unlike
-- bl_protected_lab.wrapped_keys (which is atomically deleted on first claim).
-- Never expose this schema, table or direct grants through Supabase Data API.
CREATE TABLE bl_protected_lab.authorized_readers (
  message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  PRIMARY KEY(message_id,user_id)
);
ALTER TABLE bl_protected_lab.authorized_readers ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE bl_protected_lab.authorized_readers
  FROM PUBLIC,anon,authenticated,service_role;

-- Returns only a message index and the encrypted *message body* (where
-- still available): NEVER E2EE wrapped keys, wrap IVs or ephemeral JWKs.
-- "metadata-only" means no decrypt key; ciphertext is optional payload.
-- Retains tombstone (consumed/expired) without returning encrypted body.
-- Only original, signer-approved, active recipient devices may list.
CREATE OR REPLACE FUNCTION public.list_my_protected_messages_v1(
  p_conversation_id uuid,
  p_device_id uuid,
  p_limit integer DEFAULT 20,
  p_before_created_at timestamptz DEFAULT NULL,
  p_before_message_id uuid DEFAULT NULL
)
RETURNS TABLE (
  message_id uuid,
  conversation_id uuid,
  sender_id uuid,
  sender_device_id uuid,
  created_at timestamptz,
  is_view_once boolean,
  expires_at timestamptz,
  availability text,
  message_ciphertext text,
  message_iv text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $protected_inbox$
DECLARE
  v_uid uuid := (SELECT auth.uid());
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF v_uid IS NULL OR p_conversation_id IS NULL OR p_device_id IS NULL
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50
     OR (p_before_message_id IS NOT NULL AND p_before_created_at IS NULL)
  THEN
    RAISE EXCEPTION 'Protected inbox unavailable' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id=p_conversation_id AND cm.user_id=v_uid
  ) OR bl_private.direct_conversation_blocked_for(p_conversation_id,v_uid)
  THEN
    RAISE EXCEPTION 'Protected inbox unavailable' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    JOIN public.messaging_device_signing_keys sk
      ON sk.device_id=d.id AND sk.user_id=d.user_id
    WHERE d.id=p_device_id AND d.user_id=v_uid
      AND d.revoked_at IS NULL AND d.key_algorithm='ECDH-P256'
      AND d.public_key_jwk IS NOT NULL
      AND sk.revoked_at IS NULL AND sk.verified_at IS NOT NULL
      AND sk.verification_method IN
         ('trusted_device_signature','audited_recovery')
  ) THEN
    RAISE EXCEPTION 'Protected inbox unavailable' USING ERRCODE='42501';
  END IF;

  RETURN QUERY
  SELECT m.id,m.conversation_id,m.sender_id,m.sender_device_id,
         m.created_at,
         (vo.message_id IS NOT NULL),
         dm.expires_at,
         CASE
           WHEN vo.consumed_at IS NOT NULL THEN 'consumed'::text
           WHEN dm.message_id IS NOT NULL AND dm.expires_at<=v_now
             THEN 'expired'::text
           ELSE 'available'::text
         END,
         CASE
           WHEN vo.consumed_at IS NOT NULL
             OR (dm.message_id IS NOT NULL AND dm.expires_at<=v_now)
           THEN NULL::text ELSE m.ciphertext END,
         CASE
           WHEN vo.consumed_at IS NOT NULL
             OR (dm.message_id IS NOT NULL AND dm.expires_at<=v_now)
           THEN NULL::text ELSE m.iv END
  FROM bl_protected_lab.authorized_readers a
  JOIN public.messages m ON m.id=a.message_id
  LEFT JOIN public.view_once_messages vo ON vo.message_id=m.id
  LEFT JOIN public.disappearing_messages dm ON dm.message_id=m.id
  WHERE a.user_id=v_uid
    AND m.conversation_id=p_conversation_id
    AND m.deleted_at IS NULL
    AND m.encryption_version=2
    AND (vo.message_id IS NOT NULL OR dm.message_id IS NOT NULL)
    AND (p_before_created_at IS NULL
       OR m.created_at<p_before_created_at
       OR (p_before_message_id IS NOT NULL
         AND m.created_at=p_before_created_at
         AND m.id<p_before_message_id))
  ORDER BY m.created_at DESC,m.id DESC
  LIMIT p_limit;
END;
$protected_inbox$;

-- Explicit no-go: this RPC is NOT enabled for app users. The test harness
-- temporarily GRANTs authenticated in its disposable PG16 container only.
REVOKE ALL ON FUNCTION public.list_my_protected_messages_v1(
  uuid,uuid,integer,timestamptz,uuid
) FROM PUBLIC,anon,authenticated,service_role;
