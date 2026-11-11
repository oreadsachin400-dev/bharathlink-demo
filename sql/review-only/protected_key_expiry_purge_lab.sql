-- REVIEW-ONLY LAB: idempotent bounded key erasure, no scheduler or grants.
-- Must never be applied to live TEST/PROD without full read-route migration.
CREATE OR REPLACE FUNCTION bl_protected_lab.purge_expired_wrapped_keys(
  p_limit integer DEFAULT 100
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $purge$
DECLARE
  v_msg uuid;
  v_count integer := 0;
BEGIN
  IF p_limit IS NULL OR p_limit<1 OR p_limit>500 THEN
    RAISE EXCEPTION 'Invalid purge batch limit' USING ERRCODE='22023';
  END IF;
  FOR v_msg IN
    SELECT dm.message_id
    FROM public.disappearing_messages dm
    WHERE dm.expires_at <= pg_catalog.clock_timestamp()
      AND dm.purged_at IS NULL
    ORDER BY dm.expires_at, dm.message_id
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  LOOP
    -- Delete ALL recipient/device decryption envelopes atomically with
    -- purged_at. Never delete chat/private browser keys from existing phones.
    DELETE FROM bl_protected_lab.wrapped_keys
      WHERE message_id=v_msg;
    UPDATE public.disappearing_messages
      SET purged_at=pg_catalog.clock_timestamp()
      WHERE message_id=v_msg AND purged_at IS NULL;
    v_count := v_count + 1;
  END LOOP;
  RETURN v_count;
END
$purge$;

-- Private schema has no Data API exposure; no client/service EXECUTE grants.
REVOKE ALL ON FUNCTION bl_protected_lab.purge_expired_wrapped_keys(integer)
 FROM PUBLIC, anon, authenticated, service_role;
