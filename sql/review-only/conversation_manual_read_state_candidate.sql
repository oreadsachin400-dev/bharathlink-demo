-- BHARATHLINK / REVIEW-ONLY / NOT FOR LIVE TEST OR PROD.
-- Based on official TEST conversation_read_settings and read getters.
-- Authenticated user may toggle ONLY their own manual-unread marker.
-- DO NOT conflate with message_receipts.read_at or mark_message_read.
-- Even though this SQL defines public SECURITY DEFINER APIs, it REVOKES
-- all EXECUTE immediately. Isolated CI alone grants/revokes temporarily.
--
-- Requires existing:
-- public.conversation_members(conversation_id,user_id)
-- public.conversation_read_settings(user_id,conversation_id,
--   manually_unread,updated_at) PK(user_id,conversation_id)
-- bl_private.direct_conversation_blocked_for(conversation_id,user_id)
CREATE OR REPLACE FUNCTION public.mark_conversation_unread(
  p_conversation_id uuid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $bl_unread$
DECLARE v_me uuid := (SELECT auth.uid());
BEGIN
  IF v_me IS NULL OR p_conversation_id IS NULL THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id=p_conversation_id AND cm.user_id=v_me
  ) OR bl_private.direct_conversation_blocked_for(p_conversation_id,v_me)
  THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  INSERT INTO public.conversation_read_settings
    (user_id,conversation_id,manually_unread,updated_at)
  VALUES (v_me,p_conversation_id,true,pg_catalog.clock_timestamp())
  ON CONFLICT (user_id,conversation_id)
  DO UPDATE SET manually_unread=true,
                updated_at=EXCLUDED.updated_at
  WHERE conversation_read_settings.manually_unread IS DISTINCT FROM true;
END;
$bl_unread$;

REVOKE ALL ON FUNCTION public.mark_conversation_unread(uuid)
  FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.mark_conversation_read(
  p_conversation_id uuid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $bl_read$
DECLARE v_me uuid := (SELECT auth.uid());
BEGIN
  IF v_me IS NULL OR p_conversation_id IS NULL THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id=p_conversation_id AND cm.user_id=v_me
  ) OR bl_private.direct_conversation_blocked_for(p_conversation_id,v_me)
  THEN
    RAISE EXCEPTION 'Conversation unavailable' USING ERRCODE='42501';
  END IF;

  -- Historical/unread receipts are deliberately NOT modified.
  INSERT INTO public.conversation_read_settings
    (user_id,conversation_id,manually_unread,updated_at)
  VALUES (v_me,p_conversation_id,false,pg_catalog.clock_timestamp())
  ON CONFLICT (user_id,conversation_id)
  DO UPDATE SET manually_unread=false,
                updated_at=EXCLUDED.updated_at
  WHERE conversation_read_settings.manually_unread IS DISTINCT FROM false;
END;
$bl_read$;

REVOKE ALL ON FUNCTION public.mark_conversation_read(uuid)
  FROM PUBLIC,anon,authenticated,service_role;
