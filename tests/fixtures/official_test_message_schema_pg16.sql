-- DISPOSABLE PostgreSQL 16 CI schema. Never run this fixture on TEST/PROD.
-- Uses realistic table names + the read-only captured public TEST sender RPC.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
AS $auth$ SELECT nullif(pg_catalog.current_setting('request.jwt.claim.sub',true),'')::uuid $auth$;
GRANT USAGE ON SCHEMA public,auth TO authenticated,anon;
CREATE TABLE public.conversations (
 id uuid PRIMARY KEY,
 conversation_type text NOT NULL
);
CREATE TABLE public.conversation_members (
 conversation_id uuid NOT NULL REFERENCES public.conversations(id),
 user_id uuid NOT NULL,
 PRIMARY KEY(conversation_id,user_id)
);
CREATE TABLE public.messaging_devices (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 revoked_at timestamptz,
 key_algorithm text NOT NULL DEFAULT 'ECDH-P256',
 public_key_jwk jsonb NOT NULL
);
-- Device signer custody approximation for independent review-only claim tests.
-- Official TEST currently has zero verified signer rows; tests seed synthetic
-- rows here and never activate the real first-device enrollment service.
CREATE TABLE public.messaging_device_signing_keys (
 device_id uuid PRIMARY KEY REFERENCES public.messaging_devices(id),
 user_id uuid NOT NULL,
 signing_public_key_jwk jsonb NOT NULL,
 verified_at timestamptz NOT NULL,
 verification_method text NOT NULL,
 revoked_at timestamptz
);
ALTER TABLE public.messaging_device_signing_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.messages (
 id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
 conversation_id uuid NOT NULL REFERENCES public.conversations(id),
 sender_id uuid NOT NULL,
 sender_device_id uuid NOT NULL REFERENCES public.messaging_devices(id),
 client_message_id uuid NOT NULL,
 ciphertext text,
 iv text,
 encryption_version integer,
 created_at timestamptz NOT NULL DEFAULT now(),
 deleted_at timestamptz
);
CREATE TABLE public.message_envelopes (
 id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
 message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
 recipient_user_id uuid NOT NULL,
 recipient_device_id uuid NOT NULL REFERENCES public.messaging_devices(id),
 ciphertext text NOT NULL,
 iv text NOT NULL,
 eph_pub jsonb,
 encryption_version integer NOT NULL
);
CREATE TABLE public.view_once_messages (
 message_id uuid PRIMARY KEY REFERENCES public.messages(id) ON DELETE CASCADE,
 conversation_id uuid NOT NULL REFERENCES public.conversations(id),
 sender_id uuid NOT NULL,
 recipient_user_id uuid NOT NULL,
 consumed_at timestamptz,
 consumed_device_id uuid,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.disappearing_messages (
 message_id uuid PRIMARY KEY REFERENCES public.messages(id) ON DELETE CASCADE,
 conversation_id uuid NOT NULL REFERENCES public.conversations(id),
 sender_id uuid NOT NULL,
 ttl_sec integer NOT NULL,
 expires_at timestamptz NOT NULL,
 purged_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.view_once_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disappearing_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_devices ENABLE ROW LEVEL SECURITY;
-- Do not grant client direct writes; only definer RPC in this fixture.

-- Captured from official TEST pg_get_functiondef read-only; no customer data.
CREATE OR REPLACE FUNCTION public.send_encrypted_message_v2(p_conversation_id uuid, p_sender_device_id uuid, p_client_message_id uuid, p_ciphertext text, p_iv text, p_envelopes jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_sender uuid := auth.uid();
  v_message_id uuid;
  v_expected integer;
  v_valid integer;
  v_item jsonb;
  v_device uuid;
  v_user uuid;
  v_seen uuid[] := ARRAY[]::uuid[];
BEGIN
  IF v_sender IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  PERFORM 1 FROM public.conversations WHERE id = p_conversation_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Conversation unavailable'; END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members
    WHERE conversation_id = p_conversation_id
      AND user_id = v_sender
  ) THEN
    RAISE EXCEPTION 'Not a conversation member';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.messaging_devices
    WHERE id = p_sender_device_id
      AND user_id = v_sender
      AND revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Sender device is not active';
  END IF;

  IF p_client_message_id IS NULL
     OR p_ciphertext IS NULL OR p_ciphertext = ''
     OR p_iv IS NULL OR p_iv = ''
     OR jsonb_typeof(p_envelopes) IS DISTINCT FROM 'array'
  THEN
    RAISE EXCEPTION 'Invalid encrypted message';
  END IF;

  SELECT COUNT(*) INTO v_expected
  FROM public.messaging_devices d
  JOIN public.conversation_members cm
    ON cm.user_id = d.user_id
  WHERE cm.conversation_id = p_conversation_id
    AND d.revoked_at IS NULL
    AND d.key_algorithm = 'ECDH-P256'
    AND d.public_key_jwk IS NOT NULL;

  IF jsonb_array_length(p_envelopes) <> v_expected
     OR v_expected = 0 THEN
    RAISE EXCEPTION 'Recipient device coverage mismatch';
  END IF;

  FOR v_item IN
    SELECT value FROM jsonb_array_elements(p_envelopes)
  LOOP
    IF jsonb_typeof(v_item) IS DISTINCT FROM 'object'
       OR (v_item->>'recipient_device_id') IS NULL
       OR (v_item->>'recipient_user_id') IS NULL
       OR (v_item->>'ciphertext') IS NULL
       OR (v_item->>'ciphertext') = ''
       OR (v_item->>'iv') IS NULL
       OR (v_item->>'iv') = ''
       OR (v_item->>'eph_pub') IS NULL
       OR (v_item->>'encryption_version') IS DISTINCT FROM '2'
    THEN
      RAISE EXCEPTION 'Invalid encryption envelope';
    END IF;

    BEGIN
      v_device := (v_item->>'recipient_device_id')::uuid;
      v_user := (v_item->>'recipient_user_id')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'Invalid recipient identifiers';
    END;

    IF v_device = ANY(v_seen) THEN
      RAISE EXCEPTION 'Duplicate recipient device';
    END IF;

    IF NOT EXISTS (
      SELECT 1
      FROM public.messaging_devices d
      JOIN public.conversation_members cm
        ON cm.user_id = d.user_id
      WHERE d.id = v_device
        AND d.user_id = v_user
        AND cm.conversation_id = p_conversation_id
        AND d.revoked_at IS NULL
        AND d.key_algorithm = 'ECDH-P256'
        AND d.public_key_jwk IS NOT NULL
    ) THEN
      RAISE EXCEPTION 'Unauthorized recipient device';
    END IF;

    v_seen := array_append(v_seen, v_device);
  END LOOP;

  INSERT INTO public.messages (
    conversation_id, sender_id, sender_device_id,
    client_message_id, ciphertext, iv, encryption_version
  )
  VALUES (
    p_conversation_id, v_sender, p_sender_device_id,
    p_client_message_id, p_ciphertext, p_iv, 2
  )
  RETURNING id INTO v_message_id;

  FOR v_item IN
    SELECT value FROM jsonb_array_elements(p_envelopes)
  LOOP
    INSERT INTO public.message_envelopes (
      message_id, recipient_user_id, recipient_device_id,
      ciphertext, iv, eph_pub, encryption_version
    )
    VALUES (
      v_message_id,
      (v_item->>'recipient_user_id')::uuid,
      (v_item->>'recipient_device_id')::uuid,
      v_item->>'ciphertext',
      v_item->>'iv',
      v_item->'eph_pub',
      2
    );
  END LOOP;

  RETURN v_message_id;
END;
$function$
;


-- Block check stub ONLY for disposable test; real TEST blocked-users schema
-- is not copied. This fixture tests protected-read metadata/expiry gaps.
CREATE SCHEMA bl_private;
CREATE FUNCTION bl_private.direct_conversation_blocked_for(uuid,uuid)
RETURNS boolean LANGUAGE sql STABLE AS $blocked$ SELECT false $blocked$;

-- Exact official TEST history retrieval RPC definition (read only snapshot).
CREATE OR REPLACE FUNCTION public.get_my_encrypted_messages_v2_for_conversation(p_device_id uuid, p_conversation_id uuid, p_limit integer DEFAULT 20, p_before_created_at timestamp with time zone DEFAULT NULL::timestamp with time zone, p_before_message_id uuid DEFAULT NULL::uuid)
 RETURNS TABLE(message_id uuid, conversation_id uuid, sender_id uuid, sender_device_id uuid, client_message_id uuid, message_ciphertext text, message_iv text, wrapped_key text, wrap_iv text, eph_pub jsonb, sender_public_key_jwk jsonb, created_at timestamp with time zone)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    WHERE d.id = p_device_id
      AND d.user_id = auth.uid()
      AND d.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Invalid device';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id = p_conversation_id
      AND cm.user_id = auth.uid()
  ) OR bl_private.direct_conversation_blocked_for(
    p_conversation_id, auth.uid()
  ) THEN
    RAISE EXCEPTION 'Conversation unavailable';
  END IF;

  RETURN QUERY
  SELECT
    m.id, m.conversation_id, m.sender_id,
    m.sender_device_id, m.client_message_id,
    m.ciphertext, m.iv,
    e.ciphertext, e.iv, e.eph_pub,
    sd.public_key_jwk, m.created_at
  FROM public.message_envelopes e
  JOIN public.messages m ON m.id = e.message_id
  JOIN public.messaging_devices sd
    ON sd.id = m.sender_device_id
   AND sd.user_id = m.sender_id
  WHERE e.recipient_user_id = auth.uid()
    AND e.recipient_device_id = p_device_id
    AND m.conversation_id = p_conversation_id
    AND m.deleted_at IS NULL
    AND e.encryption_version = 2
    AND m.encryption_version = 2
    AND m.client_message_id IS NOT NULL
    AND m.ciphertext IS NOT NULL
    AND m.iv IS NOT NULL
    AND e.eph_pub IS NOT NULL
    AND (
      p_before_created_at IS NULL
      OR m.created_at < p_before_created_at
      OR (
        m.created_at = p_before_created_at
        AND p_before_message_id IS NOT NULL
        AND m.id < p_before_message_id
      )
    )
  ORDER BY m.created_at DESC, m.id DESC
  LIMIT LEAST(GREATEST(COALESCE(p_limit, 20), 1), 50);
END;
$function$
;
