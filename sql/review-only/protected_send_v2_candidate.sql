-- REVIEW ONLY. Do not run on active BharathLink TEST or PROD.
-- V1 protected message send contract: atomic metadata registration only.
-- RELEASE HOLD: Direct envelope access, the history RPC, claim flow and TTL
-- key-erasure job have not been reconciled. EXECUTE stays denied.
CREATE OR REPLACE FUNCTION public.send_protected_encrypted_message_v2(
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
AS $bl_protected$
DECLARE
  v_sender uuid := auth.uid();
  v_type text;
  v_member_count integer;
  v_sender_count integer;
  v_recipient uuid;
  v_message_id uuid;
BEGIN
  IF v_sender IS NULL THEN
    RAISE EXCEPTION 'Authentication required' USING ERRCODE='42501';
  END IF;
  IF p_conversation_id IS NULL OR p_sender_device_id IS NULL
     OR p_client_message_id IS NULL THEN
    RAISE EXCEPTION 'Invalid protected send identifiers' USING ERRCODE='22023';
  END IF;
  IF p_view_once IS NULL OR (NOT p_view_once AND p_disappearing_ttl_sec IS NULL) THEN
    RAISE EXCEPTION 'Protection mode required' USING ERRCODE='22023';
  END IF;
  IF p_disappearing_ttl_sec IS NOT NULL
     AND p_disappearing_ttl_sec NOT IN (30, 3600, 86400, 604800, 7776000)
  THEN
    RAISE EXCEPTION 'Unsupported disappearing TTL' USING ERRCODE='22023';
  END IF;

  -- Same conversation lock as the existing encrypted-send function.
  -- Locks alone do not prove complete membership mutation serialization.
  SELECT c.conversation_type INTO v_type
  FROM public.conversations c WHERE c.id = p_conversation_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  IF p_view_once THEN
    -- Current metadata schema has ONE recipient row per message. Do not
    -- claim to support group view-once or multi-recipient semantics.
    IF v_type IS DISTINCT FROM 'direct' THEN
      RAISE EXCEPTION 'View once requires a direct conversation' USING ERRCODE='22023';
    END IF;
    SELECT count(*)::integer,
           count(*) FILTER (WHERE cm.user_id = v_sender)::integer,
           (array_agg(cm.user_id) FILTER (WHERE cm.user_id <> v_sender))[1]
      INTO v_member_count, v_sender_count, v_recipient
    FROM public.conversation_members cm
    WHERE cm.conversation_id = p_conversation_id;
    IF v_member_count <> 2 OR v_sender_count <> 1 OR v_recipient IS NULL THEN
      RAISE EXCEPTION 'View once requires exactly two distinct members'
        USING ERRCODE='42501';
    END IF;
  END IF;

  -- The real existing function checks auth.uid, sender device, recipient
  -- coverage, duplicate devices and encrypted envelope shape.
  -- A failure in ANY statement here rolls back the full RPC transaction.
  v_message_id := public.send_encrypted_message_v2(
    p_conversation_id, p_sender_device_id, p_client_message_id,
    p_ciphertext, p_iv, p_envelopes
  );

  IF p_view_once THEN
    INSERT INTO public.view_once_messages
      (message_id, conversation_id, sender_id, recipient_user_id)
    VALUES
      (v_message_id, p_conversation_id, v_sender, v_recipient);
  END IF;

  IF p_disappearing_ttl_sec IS NOT NULL THEN
    INSERT INTO public.disappearing_messages
      (message_id, conversation_id, sender_id, ttl_sec, expires_at)
    VALUES
      (v_message_id, p_conversation_id, v_sender,
       p_disappearing_ttl_sec,
       pg_catalog.clock_timestamp() +
         (p_disappearing_ttl_sec * interval '1 second'));
  END IF;
  RETURN v_message_id;
END;
$bl_protected$;

-- IMPORTANT: Both global PUBLIC defaults and Supabase direct role grants
-- may expose a SECURITY DEFINER RPC. Keep unavailable until independent
-- view-once claim/read gate and expiry/cleanup are approved + tested.
REVOKE ALL ON FUNCTION public.send_protected_encrypted_message_v2(
  uuid,uuid,uuid,text,text,jsonb,integer,boolean
) FROM PUBLIC, anon, authenticated, service_role;
