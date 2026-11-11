-- REVIEW ONLY: ISOLATED PG16 PROTOTYPE. NEVER APPLY TO ACTIVE TEST/PROD.
-- No existing protected-send function is safe to release. Current TEST history
-- RPC and Data API allow the wrapped keys of ordinary message_envelopes to be
-- read without a claim. Keys for THIS prototype must live ONLY in this vault.
-- Caller grants are intentionally REVOKED. The test suite grants temporarily.
CREATE SCHEMA IF NOT EXISTS bl_protected_lab;
REVOKE ALL ON SCHEMA bl_protected_lab FROM PUBLIC, anon, authenticated, service_role;

-- Dedicated private wrapped-key vault; not in exposed public schema.
CREATE TABLE bl_protected_lab.wrapped_keys (
  message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
  recipient_user_id uuid NOT NULL,
  recipient_device_id uuid NOT NULL REFERENCES public.messaging_devices(id),
  wrapped_key text NOT NULL CHECK (length(wrapped_key)>0),
  wrap_iv text NOT NULL CHECK (length(wrap_iv)>0),
  eph_pub jsonb NOT NULL,
  PRIMARY KEY(message_id,recipient_device_id)
);
ALTER TABLE bl_protected_lab.wrapped_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE bl_protected_lab.wrapped_keys
  FROM PUBLIC, anon, authenticated, service_role;

-- IMPORTANT: the actual TEST messaging_device_signing_keys is reviewed
-- separately. It must exist on target; this lab does NOT invent a bootstrap.
-- Zero verified signing keys in current TEST => legitimate users fail closed.

CREATE OR REPLACE FUNCTION public.claim_protected_wrapped_key_v1(
  p_message_id uuid,
  p_device_id uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $bl_claim$
DECLARE
  v_uid uuid := auth.uid();
  v_chat uuid;
  v_deleted timestamptz;
  v_version integer;
  v_vo_recipient uuid;
  v_vo_conversation uuid;
  v_consumed timestamptz;
  v_once boolean;
  v_ttl_chat uuid;
  v_expires timestamptz;
  v_ttl boolean;
  v_key text;
  v_iv text;
  v_ephemeral jsonb;
  v_now timestamptz;
BEGIN
  IF v_uid IS NULL OR p_message_id IS NULL OR p_device_id IS NULL THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  -- Lock the one-per-message consumption row BEFORE reading the device key.
  -- Competing devices must serialize on the same row; second sees consumed.
  SELECT vo.recipient_user_id,vo.consumed_at,vo.conversation_id
    INTO v_vo_recipient,v_consumed,v_vo_conversation
  FROM public.view_once_messages vo
  WHERE vo.message_id=p_message_id
  FOR UPDATE;
  v_once := FOUND;

  SELECT dm.conversation_id,dm.expires_at
    INTO v_ttl_chat,v_expires
  FROM public.disappearing_messages dm
  WHERE dm.message_id=p_message_id
  FOR SHARE;
  v_ttl := FOUND;
  IF NOT v_once AND NOT v_ttl THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;
  v_now := pg_catalog.clock_timestamp();

  IF (v_once AND (v_vo_recipient IS DISTINCT FROM v_uid OR v_consumed IS NOT NULL))
     OR (v_ttl AND (v_expires IS NULL OR v_expires<=v_now)) THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  SELECT m.conversation_id,m.deleted_at,m.encryption_version
    INTO v_chat,v_deleted,v_version
  FROM public.messages m
  WHERE m.id=p_message_id FOR SHARE;
  IF NOT FOUND OR v_deleted IS NOT NULL OR v_version IS DISTINCT FROM 2
     OR (v_once AND v_vo_conversation IS DISTINCT FROM v_chat)
     OR (v_ttl AND v_ttl_chat IS DISTINCT FROM v_chat) THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM public.conversation_members cm
     WHERE cm.conversation_id=v_chat AND cm.user_id=v_uid)
     OR bl_private.direct_conversation_blocked_for(v_chat,v_uid) THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  -- Owner + non-revoked ECDH device AND independently verified signing key.
  IF NOT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    JOIN public.messaging_device_signing_keys sk
      ON sk.device_id=d.id AND sk.user_id=d.user_id
    WHERE d.id=p_device_id AND d.user_id=v_uid AND d.revoked_at IS NULL
      AND d.key_algorithm='ECDH-P256'
      AND sk.revoked_at IS NULL AND sk.verified_at IS NOT NULL
      AND sk.verification_method IN ('trusted_device_signature','audited_recovery')
  ) THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  -- Strong invariant: if ANY public envelope exists, the key was already
  -- retrievable through normal history/Data API. Deny instead of claiming a
  -- false View Once guarantee. Sender migration must guarantee vault-only.
  IF EXISTS (SELECT 1 FROM public.message_envelopes pe
             WHERE pe.message_id=p_message_id) THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  SELECT k.wrapped_key,k.wrap_iv,k.eph_pub
    INTO v_key,v_iv,v_ephemeral
  FROM bl_protected_lab.wrapped_keys k
  WHERE k.message_id=p_message_id AND k.recipient_user_id=v_uid
    AND k.recipient_device_id=p_device_id;
  IF NOT FOUND OR v_key IS NULL OR v_iv IS NULL OR v_ephemeral IS NULL THEN
    RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
  END IF;

  IF v_once THEN
    UPDATE public.view_once_messages
    SET consumed_at=pg_catalog.clock_timestamp(),consumed_device_id=p_device_id
    WHERE message_id=p_message_id AND consumed_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Protected claim denied' USING ERRCODE='42501';
    END IF;
    -- Destroy all alternate-device key envelopes before commit.
    DELETE FROM bl_protected_lab.wrapped_keys WHERE message_id=p_message_id;
  END IF;

  -- Only returns the caller device's already-E2EE-wrapped key, not plaintext.
  RETURN pg_catalog.jsonb_build_object(
    'wrappedKey',v_key,'wrapIv',v_iv,'ephPub',v_ephemeral,
    'viewOnce',v_once,'expiresAt',v_expires
  );
END;
$bl_claim$;

-- Do not expose without full protected-send + other read-path migration.
REVOKE ALL ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid)
  FROM PUBLIC,anon,authenticated,service_role;
