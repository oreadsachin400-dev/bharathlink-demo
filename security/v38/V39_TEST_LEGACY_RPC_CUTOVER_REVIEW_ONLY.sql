-- V39 TEST ONLY. REVIEW-ONLY. DO NOT RUN ON LIVE OR TEST UNTIL REPLACEMENT IS READY.
-- This cutover is intentionally not executed automatically.
BEGIN;
REVOKE EXECUTE ON FUNCTION public.register_e2ee_v2_device(uuid,text,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.register_e2ee_v2_device(uuid,text,text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.register_e2ee_v2_device(uuid,text,text) FROM authenticated;
-- Assert neither API role can execute (including privileges inherited from PUBLIC).
DO $$
BEGIN
 IF has_function_privilege('authenticated','public.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 OR has_function_privilege('anon','public.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'legacy registration RPC still executable'; END IF;
END $$;
-- Commit is deliberately absent: this artifact is a review-only cutover fragment.
ROLLBACK;
