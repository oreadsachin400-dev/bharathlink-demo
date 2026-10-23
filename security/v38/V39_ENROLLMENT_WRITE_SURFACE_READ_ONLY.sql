-- V39 read-only enrollment write-surface inventory (TEST only).
-- Run with a privileged READ-ONLY SQL session; do not run migrations from this file.
-- These results are evidence to review, not permission to enable enrollment.
-- Do not use this query against production as part of TEST cutover.
BEGIN READ ONLY;
SELECT current_database() AS database_name, current_setting('server_version') AS postgres_version;
-- List effective role grants for both distinct device registries.
SELECT t.table_schema,t.table_name,r.rolname AS role_name,
       has_table_privilege(r.rolname,format('%I.%I',t.table_schema,t.table_name),'INSERT') AS can_insert,
       has_table_privilege(r.rolname,format('%I.%I',t.table_schema,t.table_name),'UPDATE') AS can_update,
       has_table_privilege(r.rolname,format('%I.%I',t.table_schema,t.table_name),'DELETE') AS can_delete
FROM information_schema.tables t
CROSS JOIN pg_roles r
WHERE t.table_schema='public'
  AND t.table_name IN ('messaging_devices','e2ee_v2_devices')
  AND r.rolname IN ('anon','authenticated','service_role')
ORDER BY t.table_name,r.rolname;
-- Policies are not equivalent to table privileges: inspect both.
SELECT schemaname,tablename,policyname,roles,cmd,qual,with_check
FROM pg_policies
WHERE schemaname='public'
  AND tablename IN ('messaging_devices','e2ee_v2_devices')
ORDER BY tablename,policyname;
-- Include overloaded functions and SECURITY DEFINER entrypoints; do not assume
-- the legacy RPC is the only enrollment writer.
SELECT n.nspname AS schema_name,p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS signature,
       p.prosecdef AS security_definer,
       has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated_execute,
       has_function_privilege('anon',p.oid,'EXECUTE') AS anon_execute
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname IN ('public','bl_pairing_private')
  AND (p.proname ILIKE '%device%' OR p.proname ILIKE '%pair%' OR p.proname ILIKE '%enroll%'
       OR p.proname ILIKE '%register%' OR p.proname ILIKE '%recover%')
ORDER BY n.nspname,p.proname,signature;
-- Trigger inventory: a safe policy can still be bypassed by a definer trigger.
SELECT n.nspname AS schema_name,c.relname AS table_name,t.tgname AS trigger_name,
       pg_get_triggerdef(t.oid) AS definition
FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE NOT t.tgisinternal AND n.nspname='public'
  AND c.relname IN ('messaging_devices','e2ee_v2_devices')
ORDER BY c.relname,t.tgname;
-- Current RLS state, including FORCE RLS.
SELECT n.nspname AS schema_name,c.relname AS table_name,
       c.relrowsecurity AS rls_enabled,c.relforcerowsecurity AS force_rls
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname IN ('messaging_devices','e2ee_v2_devices');
COMMIT;
