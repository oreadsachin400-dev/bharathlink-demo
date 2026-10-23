-- V39 TEST cutover preflight: READ ONLY. Never deploy or revoke anything here.
-- Execute only against TEST project fsdusofbpwdrdvgexxyw.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT n.nspname AS schema_name,c.relname AS table_name,
       c.relrowsecurity AS rls_enabled,c.relforcerowsecurity AS force_rls,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS policy_count
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE (n.nspname='public' AND c.relname IN ('messaging_devices','e2ee_v2_devices'))
   OR (n.nspname='bl_pairing_private' AND c.relname IN ('requests','trust_anchors'))
ORDER BY 1,2;
SELECT n.nspname AS schema_name,p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS signature,
       p.prosecdef AS security_definer,
       has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated_execute,
       has_function_privilege('anon',p.oid,'EXECUTE') AS anon_execute
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname IN ('public','bl_pairing_private')
 AND (p.proname ILIKE '%device%' OR p.proname ILIKE '%enroll%' OR p.proname ILIKE '%pair%')
ORDER BY 1,2,3;
SELECT n.nspname AS schema_name,c.relname AS table_name,
       has_table_privilege('authenticated',c.oid,'INSERT') AS authenticated_insert,
       has_table_privilege('authenticated',c.oid,'UPDATE') AS authenticated_update,
       has_table_privilege('anon',c.oid,'INSERT') AS anon_insert
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname IN ('messaging_devices','e2ee_v2_devices')
ORDER BY 1,2;
COMMIT;
