-- BHARATHLINK V1 / REVIEW ONLY / DISPOSABLE PG16 PROTOTYPE
-- NOT A MIGRATION. NEVER APPLY TO TEST OR PROD.
-- Distinct name to prevent accidental activation of legacy protected sender.
-- No user-facing EXECUTE grants; CI grants authenticated ONLY temporarily.
-- This function writes encrypted per-device keys ONLY into a private vault.
-- It must NOT call public.send_encrypted_message_v2, which inserts normal,
-- independently readable public.message_envelopes.
-- Normal messaging sender is left unchanged.

CREATE OR REPLACE FUNCTION public.send_protected_vault_message_v1(
  p_conversation_id uuid,
  p_sender_device_id uuid,
  p_client_message_id uuid,
  p_ciphertext text,
  p_iv text,
  p_envelopes jsonb,
  p_disappearing_ttl_sec integer DEFAULT NULL,
  p_view_once boolean DEFAULT false
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $vaultsend$
DECLARE
  v_sender uuid := (SELECT auth.uid());
  v_conversation_type text;
  v_member_count integer;
  v_sender_count integer;
  v_recipient uuid;
  v_expected integer;
  v_message_id uuid;
  v_item jsonb;
  v_recipient_id uuid;
  v_device_id uuid;
  v_seen uuid[] := ARRAY[]::uuid[];
BEGIN
  IF v_sender IS NULL OR p_conversation_id IS NULL
    OR p_sender_device_id IS NULL OR p_client_message_id IS NULL
  THEN
    RAISE EXCEPTION 'Protected send denied' USING ERRCODE='42501';
  END IF;
  IF p_view_once IS NULL OR
    (NOT p_view_once AND p_disappearing_ttl_sec IS NULL)
  THEN
    RAISE EXCEPTION 'Protection mode required' USING ERRCODE='22023';
  END IF;
  IF p_disappearing_ttl_sec IS NOT NULL AND
    p_disappearing_ttl_sec NOT IN (30,3600,86400,604800,7776000)
  THEN
    RAISE EXCEPTION 'Unsupported TTL' USING ERRCODE='22023';
  END IF;
  IF p_ciphertext IS NULL OR length(p_ciphertext) NOT BETWEEN 1 AND 1048576
    OR p_iv IS NULL OR length(p_iv) NOT BETWEEN 1 AND 128
    OR pg_catalog.jsonb_typeof(p_envelopes) IS DISTINCT FROM 'array'
  THEN
    RAISE EXCEPTION 'Invalid encrypted payload' USING ERRCODE='22023';
  END IF;
  IF pg_catalog.jsonb_array_length(p_envelopes) NOT BETWEEN 1 AND 128
    OR length(p_envelopes::text)>1048576
  THEN
    RAISE EXCEPTION 'Invalid envelope batch size' USING ERRCODE='22023';
  END IF;

  -- Serialize senders in this conversation while checking membership/devices.
  SELECT c.conversation_type INTO v_conversation_type
  FROM public.conversations c
  WHERE c.id=p_conversation_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id=p_conversation_id AND cm.user_id=v_sender
  ) OR bl_private.direct_conversation_blocked_for(
    p_conversation_id,v_sender
  ) THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  -- Approved sender signer is mandatory. There is no first-device shortcut.
  IF NOT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    JOIN public.messaging_device_signing_keys sk
      ON sk.device_id=d.id AND sk.user_id=d.user_id
    WHERE d.id=p_sender_device_id AND d.user_id=v_sender
      AND d.revoked_at IS NULL AND d.key_algorithm='ECDH-P256'
      AND d.public_key_jwk IS NOT NULL
      AND sk.revoked_at IS NULL AND sk.verified_at IS NOT NULL
      AND sk.verification_method IN ('trusted_device_signature','audited_recovery')
  ) THEN
    RAISE EXCEPTION 'Sender device not trusted' USING ERRCODE='42501';
  END IF;

  IF p_view_once THEN
    IF v_conversation_type IS DISTINCT FROM 'direct' THEN
      RAISE EXCEPTION 'View Once only available in direct chat' USING ERRCODE='22023';
    END IF;
    SELECT count(*)::integer,
      count(*) FILTER (WHERE cm.user_id=v_sender)::integer,
      (array_agg(cm.user_id) FILTER (WHERE cm.user_id<>v_sender))[1]
    INTO v_member_count,v_sender_count,v_recipient
    FROM public.conversation_members cm
    WHERE cm.conversation_id=p_conversation_id;
    IF v_member_count<>2 OR v_sender_count<>1 OR v_recipient IS NULL THEN
      RAISE EXCEPTION 'Direct View Once requires two distinct chat members'
        USING ERRCODE='42501';
    END IF;
  END IF;

  -- All nonrevoked ECDH devices for ALL conversation members must be covered,
  -- exactly once each. A missing verified signer blocks the entire send.
  SELECT count(*)::integer INTO v_expected
  FROM public.messaging_devices d
  JOIN public.conversation_members cm ON cm.user_id=d.user_id
  WHERE cm.conversation_id=p_conversation_id
    AND d.revoked_at IS NULL
    AND d.key_algorithm='ECDH-P256'
    AND d.public_key_jwk IS NOT NULL;

  IF v_expected=0 OR v_expected>128 OR
    pg_catalog.jsonb_array_length(p_envelopes)<>v_expected THEN
    RAISE EXCEPTION 'Recipient device coverage mismatch' USING ERRCODE='42501';
  END IF;

  FOR v_item IN SELECT value FROM
    pg_catalog.jsonb_array_elements(p_envelopes)
  LOOP
    IF pg_catalog.jsonb_typeof(v_item) IS DISTINCT FROM 'object'
      OR pg_catalog.jsonb_typeof(v_item->'recipient_user_id') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(v_item->'recipient_device_id') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(v_item->'ciphertext') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(v_item->'iv') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(v_item->'eph_pub') IS DISTINCT FROM 'object'
      OR v_item->>'encryption_version' IS DISTINCT FROM '2'
      OR length(v_item->>'ciphertext') NOT BETWEEN 1 AND 16384
      OR length(v_item->>'iv') NOT BETWEEN 1 AND 128
      OR length((v_item->'eph_pub')::text)>4096 THEN
      RAISE EXCEPTION 'Malformed wrapped key envelope' USING ERRCODE='22023';
    END IF;

    BEGIN
      v_recipient_id := (v_item->>'recipient_user_id')::uuid;
      v_device_id := (v_item->>'recipient_device_id')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'Invalid recipient identifier' USING ERRCODE='22023';
    END;

    IF v_device_id=ANY(v_seen) THEN
      RAISE EXCEPTION 'Duplicate recipient device' USING ERRCODE='22023';
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM public.messaging_devices d
      JOIN public.conversation_members cm ON cm.user_id=d.user_id
      JOIN public.messaging_device_signing_keys sk
        ON sk.device_id=d.id AND sk.user_id=d.user_id
      WHERE d.id=v_device_id AND d.user_id=v_recipient_id
        AND cm.conversation_id=p_conversation_id
        AND d.revoked_at IS NULL AND d.key_algorithm='ECDH-P256'
        AND d.public_key_jwk IS NOT NULL
        AND sk.revoked_at IS NULL AND sk.verified_at IS NOT NULL
        AND sk.verification_method IN ('trusted_device_signature','audited_recovery')
    ) THEN
      RAISE EXCEPTION 'Untrusted or unauthorized recipient device'
        USING ERRCODE='42501';
    END IF;
    v_seen := pg_catalog.array_append(v_seen,v_device_id);
  END LOOP;

  -- The official TEST schema has a unique (sender_id,client_message_id)
  -- index. Its violation aborts the whole transaction on re-send.
  INSERT INTO public.messages(
    conversation_id,sender_id,sender_device_id,client_message_id,
    ciphertext,iv,encryption_version
  ) VALUES (
    p_conversation_id,v_sender,p_sender_device_id,p_client_message_id,
    p_ciphertext,p_iv,2
  ) RETURNING id INTO v_message_id;

  IF p_view_once THEN
    INSERT INTO public.view_once_messages(
      message_id,conversation_id,sender_id,recipient_user_id
    ) VALUES (
      v_message_id,p_conversation_id,v_sender,v_recipient
    );
  END IF;

  IF p_disappearing_ttl_sec IS NOT NULL THEN
    INSERT INTO public.disappearing_messages(
      message_id,conversation_id,sender_id,ttl_sec,expires_at
    ) VALUES (
      v_message_id,p_conversation_id,v_sender,p_disappearing_ttl_sec,
      pg_catalog.clock_timestamp()+
        (p_disappearing_ttl_sec*interval '1 second')
    );
  END IF;

  -- Deliberately NO public.message_envelopes INSERT.
  -- Direct history/RLS/Realtime cannot retrieve a wrapped key for this
  -- message. Vault row, metadata and message share one transaction.
  FOR v_item IN SELECT value FROM
    pg_catalog.jsonb_array_elements(p_envelopes)
  LOOP
    INSERT INTO bl_protected_lab.wrapped_keys(
      message_id,recipient_user_id,recipient_device_id,
      wrapped_key,wrap_iv,eph_pub
    ) VALUES (
      v_message_id,
      (v_item->>'recipient_user_id')::uuid,
      (v_item->>'recipient_device_id')::uuid,
      v_item->>'ciphertext',
      v_item->>'iv',
      v_item->'eph_pub'
    );
  END LOOP;

  RETURN v_message_id;
END;
$vaultsend$;

-- Do NOT enable, even if the above compiles successfully.
REVOKE ALL ON FUNCTION public.send_protected_vault_message_v1(
  uuid,uuid,uuid,text,text,jsonb,integer,boolean
) FROM PUBLIC,anon,authenticated,service_role;
