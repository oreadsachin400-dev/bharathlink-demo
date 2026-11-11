-- Disposable PostgreSQL 16 only. Synthetic IDs and data; no live TEST/PROD.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid
 LANGUAGE sql STABLE
 AS $uid$ SELECT nullif(pg_catalog.current_setting('request.jwt.claim.sub',true),'')::uuid $uid$;
GRANT USAGE ON SCHEMA public,auth TO anon,authenticated;
CREATE SCHEMA bl_private;
-- Synthetic test predicate: controlled through a SET variable for one user.
-- NOT the actual production blocked-user implementation.
CREATE FUNCTION bl_private.direct_conversation_blocked_for(uuid,uuid)
RETURNS boolean LANGUAGE sql STABLE AS $blocked$
  SELECT $1='dddddddd-dddd-4ddd-8ddd-dddddddddddd'::uuid
   AND $2::text=nullif(pg_catalog.current_setting('bhl.lab.blocked_uid',true),'')
$blocked$;

CREATE TABLE public.conversations(
 id uuid PRIMARY KEY,
 conversation_type text NOT NULL DEFAULT 'direct'
);
CREATE TABLE public.conversation_members(
 conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
 user_id uuid NOT NULL,
 PRIMARY KEY(conversation_id,user_id)
);
CREATE TABLE public.conversation_read_settings(
 user_id uuid NOT NULL,
 conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
 manually_unread boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,conversation_id)
);
CREATE TABLE public.messages(
 id uuid PRIMARY KEY,
 conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
 sender_id uuid NOT NULL,
 deleted_at timestamptz
);
CREATE TABLE public.message_receipts(
 message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
 user_id uuid NOT NULL,
 delivered_at timestamptz,
 read_at timestamptz,
 PRIMARY KEY(message_id,user_id)
);

ALTER TABLE public.conversation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_read_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC,anon,authenticated,service_role;

-- Genuine read getter function definitions copied from official TEST
-- pg_get_functiondef metadata; no real account data exported.

-- get_conversation_read_state
CREATE OR REPLACE FUNCTION public.get_conversation_read_state(p_conversation_id uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_me uuid := auth.uid();
  v_state boolean := false;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.conversation_members cm
    WHERE cm.conversation_id = p_conversation_id
      AND cm.user_id = v_me
  ) OR bl_private.direct_conversation_blocked_for(
    p_conversation_id, v_me
  ) THEN
    RAISE EXCEPTION 'Conversation unavailable';
  END IF;

  SELECT r.manually_unread
  INTO v_state
  FROM public.conversation_read_settings r
  WHERE r.user_id = v_me
    AND r.conversation_id = p_conversation_id;

  RETURN COALESCE(v_state, false);
END;
$function$
;

-- get_my_unread_conversations
CREATE OR REPLACE FUNCTION public.get_my_unread_conversations()
 RETURNS TABLE(conversation_id uuid, updated_at timestamp with time zone)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  SELECT r.conversation_id, r.updated_at
  FROM public.conversation_read_settings r
  JOIN public.conversation_members cm
    ON cm.conversation_id = r.conversation_id
   AND cm.user_id = auth.uid()
  WHERE r.user_id = auth.uid()
    AND r.manually_unread = true
  ORDER BY r.updated_at DESC;
$function$
;
