-- READ-ONLY deployment preflight. Run manually on TEST before proposing any
-- enrollment migration. Never treats existing authentication as device approval.
-- Expected current legacy posture is INSECURE; deployment MUST remain blocked.
WITH grants AS (
 SELECT
  has_function_privilege('authenticated',
   'public.register_e2ee_v2_device(uuid,text,text)'::regprocedure,'EXECUTE') AS legacy_rpc_exposed,
  EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public'
   AND tablename='messaging_devices' AND cmd='INSERT'
   AND roles @> ARRAY['authenticated']::name[]
   AND with_check='(user_id = auth.uid())') AS direct_insert_exposed
), keys AS (
 SELECT
  EXISTS(SELECT 1 FROM information_schema.columns
   WHERE table_schema='public' AND table_name='messaging_devices'
     AND column_name='public_key_jwk') AS messaging_ecdh_key_present,
  EXISTS(SELECT 1 FROM information_schema.columns
   WHERE table_schema='bl_pairing_private' AND table_name='trust_anchors'
     AND column_name='signing_public_key') AS signing_anchor_present
)
SELECT grants.*,keys.*,
 CASE WHEN legacy_rpc_exposed OR direct_insert_exposed
 THEN 'BLOCK: enrollment bypass remains available'
 ELSE 'REVIEW REQUIRED: verify every write path and atomic signature enforcement'
 END AS migration_gate
FROM grants CROSS JOIN keys;
