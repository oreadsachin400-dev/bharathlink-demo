-- Read-only hosted TEST audit. No secrets or account identifiers are returned.
SELECT c.relname AS table_name,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS force_rls,
       has_table_privilege('authenticated',c.oid,'SELECT') AS authenticated_can_select,
       has_table_privilege('authenticated',c.oid,'INSERT') AS authenticated_can_insert,
       has_table_privilege('anon',c.oid,'SELECT') AS anon_can_select
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='bl_enrollment_v39_private' AND c.relkind='r'
ORDER BY c.relname;
SELECT
 (SELECT count(*) FROM bl_enrollment_v39_private.approval_requests) AS pending_and_historical_requests,
 (SELECT count(*) FROM bl_enrollment_v39_private.verified_approvers) AS verified_approvers,
 (SELECT count(*) FROM bl_enrollment_v39_private.enrollment_receipts) AS receipts;
-- Counts of zero do not establish whether any preexisting V2 device is a
-- trustworthy approver. Never auto-import existing devices as verified anchors.
