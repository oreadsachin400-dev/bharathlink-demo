-- V39 PROPOSED additive schema; REVIEW ONLY, NOT APPROVED FOR DEPLOYMENT.
-- Targets the observed TEST schema without modifying its existing registration RPC.
-- This SQL is deliberately fail-closed until the authenticated signed-enrollment
-- service and complete client cutover are independently reviewed.
BEGIN;
-- Disposable CI fixture: Supabase roles are present on hosted Supabase, but
-- absent on a plain PostgreSQL container. Transactional and rolled back.
DO $fixture_roles$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
   CREATE ROLE anon NOLOGIN;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
   CREATE ROLE authenticated NOLOGIN;
 END IF;
END
$fixture_roles$;
CREATE SCHEMA IF NOT EXISTS bl_enrollment_v39_private;
REVOKE ALL ON SCHEMA bl_enrollment_v39_private FROM PUBLIC, anon, authenticated;
CREATE TABLE bl_enrollment_v39_private.approval_requests (
 request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL,
 approver_device_id uuid NOT NULL,
 signing_public_key text NOT NULL,
 curve25519_public_key text NOT NULL,
 candidate_key_sha256 text NOT NULL CHECK(candidate_key_sha256 ~ '^[0-9a-f]{64}$'),
 nonce_sha256 text NOT NULL CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','consumed','cancelled')),
 created_at timestamptz NOT NULL DEFAULT now(),
 consumed_at timestamptz,
 CHECK ((state='consumed')=(consumed_at IS NOT NULL)),
 UNIQUE (account_id,candidate_device_id)
);
CREATE TABLE bl_enrollment_v39_private.verified_approvers (
 account_id uuid NOT NULL,
 device_id uuid NOT NULL,
 signing_public_key_jwk jsonb NOT NULL,
 verified_at timestamptz NOT NULL,
 revoked_at timestamptz,
 PRIMARY KEY(account_id,device_id)
);
CREATE TABLE bl_enrollment_v39_private.enrollment_receipts (
 request_id uuid PRIMARY KEY REFERENCES bl_enrollment_v39_private.approval_requests(request_id),
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL UNIQUE,
 candidate_key_sha256 text NOT NULL,
 approved_by_device_id uuid NOT NULL,
 committed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE bl_enrollment_v39_private.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_enrollment_v39_private.verified_approvers ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_enrollment_v39_private.enrollment_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_enrollment_v39_private.approval_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE bl_enrollment_v39_private.verified_approvers FORCE ROW LEVEL SECURITY;
ALTER TABLE bl_enrollment_v39_private.enrollment_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_enrollment_v39_private FROM PUBLIC, anon, authenticated;
-- In-transaction security assertions: fail the disposable CI if a grant,
-- RLS setting or single-use constraint is accidentally weakened.
DO $assert_boundary$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['approval_requests','verified_approvers','enrollment_receipts']
 LOOP
  IF NOT EXISTS (
   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='bl_enrollment_v39_private' AND c.relname=t
     AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN RAISE EXCEPTION 'RLS/FORCE RLS missing on %',t; END IF;
  IF has_table_privilege('authenticated',format('bl_enrollment_v39_private.%I',t),'INSERT')
     OR has_table_privilege('anon',format('bl_enrollment_v39_private.%I',t),'SELECT')
  THEN RAISE EXCEPTION 'client table privilege exposed: %',t; END IF;
 END LOOP;
 IF has_schema_privilege('authenticated','bl_enrollment_v39_private','USAGE')
    OR has_schema_privilege('anon','bl_enrollment_v39_private','USAGE')
 THEN RAISE EXCEPTION 'private enrollment schema exposed'; END IF;
 IF NOT EXISTS (
  SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
  JOIN pg_namespace n ON n.oid=t.relnamespace
  WHERE n.nspname='bl_enrollment_v39_private'
    AND t.relname='enrollment_receipts' AND c.contype='p'
 ) THEN RAISE EXCEPTION 'receipt request primary key missing'; END IF;
END
$assert_boundary$;
-- No RPCs, grants or policies added: nothing can enroll a device via this schema.
-- Do not apply this proposal until a verified trusted-anchor source,
-- service ownership, signature verification, first-device bootstrap,
-- old-RPC closure and rollback strategy have been approved.
ROLLBACK;
