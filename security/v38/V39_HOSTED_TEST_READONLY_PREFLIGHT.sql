-- Read-only hosted TEST readiness report. Never changes database state.
-- Run only against the explicitly selected BharathLink 20-user TEST project.
WITH gates AS (
 SELECT 'v2_device_table_exists' gate, to_regclass('public.e2ee_v2_devices') IS NOT NULL ok
 UNION ALL SELECT 'v39_private_schema_exists', EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='bl_enrollment_v39_private')
 UNION ALL SELECT 'v39_pending_requests_exists',to_regclass('bl_enrollment_v39_private.approval_requests') IS NOT NULL
 UNION ALL SELECT 'v39_approvers_exists',to_regclass('bl_enrollment_v39_private.verified_approvers') IS NOT NULL
 UNION ALL SELECT 'v39_receipts_exists',to_regclass('bl_enrollment_v39_private.enrollment_receipts') IS NOT NULL
 UNION ALL SELECT 'legacy_rpc_closed_to_authenticated',
  NOT has_function_privilege('authenticated','public.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 UNION ALL SELECT 'legacy_rpc_closed_to_anon',
  NOT has_function_privilege('anon','public.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 UNION ALL SELECT 'v2_direct_insert_denied',
  NOT has_table_privilege('authenticated','public.e2ee_v2_devices','INSERT')
)
SELECT gate, CASE WHEN ok THEN 'PASS' ELSE 'BLOCKED' END AS status FROM gates ORDER BY gate;
-- This query cannot establish independent initial-device or recovery authority.
-- No enrollment deployment is authorized merely because all SQL gates pass.
