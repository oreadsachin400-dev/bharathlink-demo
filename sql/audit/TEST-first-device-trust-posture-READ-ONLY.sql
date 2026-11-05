-- BharathLink Phase7J — SQL EDITOR READ-ONLY TRUST POSTURE CHECK.
-- Approved for read-only TEST inspection only. No mutation, no secret values.
-- Privileged SQL editor access is required to count trust tables safely.
-- This query NEVER determines device activation eligibility by itself.
WITH insert_policies AS (
 SELECT permissive, cmd, with_check FROM pg_catalog.pg_policies
 WHERE schemaname='public' AND tablename='messaging_devices'
   AND cmd IN ('INSERT','ALL')
),
device_state AS (
 SELECT c.relrowsecurity AS rls_enabled FROM pg_catalog.pg_class c
 WHERE c.oid='public.messaging_devices'::regclass
)
SELECT
 pg_catalog.clock_timestamp() AS observed_at_utc,
 (SELECT count(*) FROM public.messaging_devices WHERE revoked_at IS NULL)
     AS active_device_count,
 (SELECT count(*) FROM public.messaging_device_signing_keys
    WHERE verified_at IS NOT NULL AND revoked_at IS NULL)
     AS verified_signer_count,
 (SELECT count(*) FROM bl_pairing_private.trust_anchors)
     AS legacy_trust_anchor_count,
 (SELECT count(*) FROM public.messaging_device_enrollment_requests
    WHERE status='pending') AS pending_enrollment_count,
 (SELECT count(*) FROM pg_catalog.pg_trigger
    WHERE tgname IN ('hard_stop_first_device_insert_and_rebind',
                     'hard_stop_first_verified_signer_and_rebind')
      AND NOT tgisinternal)
     AS first_device_hold_trigger_count,
 ((SELECT rls_enabled FROM device_state) IS TRUE
  AND EXISTS(SELECT 1 FROM insert_policies
             WHERE cmd='INSERT' AND with_check='false')
  AND NOT EXISTS(SELECT 1 FROM insert_policies
                  WHERE permissive='PERMISSIVE'
                    AND (with_check IS NULL OR with_check<>'false')))
     AS direct_authenticated_insert_fail_closed,
 pg_catalog.has_function_privilege(
   'service_role','public.bl20_commit_device_approval(uuid,uuid,uuid,text,text)',
   'EXECUTE') AS legacy_v1_approval_service_executable;
