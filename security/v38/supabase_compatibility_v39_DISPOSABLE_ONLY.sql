-- V39 Supabase compatibility boundary exercise.
-- DISPOSABLE POSTGRES ONLY. Do not apply to TEST or production.
-- Verifies representative current TEST table names/columns, RLS isolation,
-- and the fact that existing enrollment RPC is not yet cryptographically bound.
BEGIN;
DO $roles$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $roles$;
CREATE SCHEMA bl_v39_compat_lab;
REVOKE ALL ON SCHEMA bl_v39_compat_lab FROM PUBLIC,anon,authenticated;
CREATE TABLE bl_v39_compat_lab.messaging_devices (
 id uuid PRIMARY KEY,user_id uuid NOT NULL,device_label text,
 public_key_jwk jsonb,key_algorithm text,revoked_at timestamptz);
CREATE TABLE bl_v39_compat_lab.e2ee_v2_devices (
 device_id uuid PRIMARY KEY,user_id uuid NOT NULL,signing_public_key text NOT NULL,
 curve25519_public_key text NOT NULL,protocol_version integer NOT NULL,revoked_at timestamptz);
CREATE TABLE bl_v39_compat_lab.pairing_requests (
 id uuid PRIMARY KEY,user_id uuid NOT NULL,candidate_public_key_jwk jsonb NOT NULL,
 challenge_nonce text NOT NULL,status text NOT NULL,expires_at timestamptz NOT NULL,
 approved_device_id uuid,approved_at timestamptz);
CREATE TABLE bl_v39_compat_lab.trust_anchors (
 device_id uuid PRIMARY KEY,user_id uuid NOT NULL,signing_public_key text NOT NULL);
CREATE TABLE bl_v39_compat_lab.approval_receipts (
 request_id uuid PRIMARY KEY,user_id uuid NOT NULL,candidate_device_id uuid NOT NULL,
 candidate_key_sha256 text NOT NULL,consumed_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE bl_v39_compat_lab.messaging_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_compat_lab.e2ee_v2_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_compat_lab.pairing_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_compat_lab.trust_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_compat_lab.approval_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_v39_compat_lab FROM PUBLIC,anon,authenticated;
DO $test$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['messaging_devices','e2ee_v2_devices','pairing_requests','trust_anchors','approval_receipts']
 LOOP
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='bl_v39_compat_lab' AND c.relname=t AND c.relrowsecurity)
  THEN RAISE EXCEPTION 'RLS missing on %',t; END IF;
 END LOOP;
 IF has_schema_privilege('authenticated','bl_v39_compat_lab','USAGE')
 OR has_schema_privilege('anon','bl_v39_compat_lab','USAGE')
 THEN RAISE EXCEPTION 'private schema exposed'; END IF;
 IF has_table_privilege('authenticated','bl_v39_compat_lab.e2ee_v2_devices','INSERT')
 OR has_table_privilege('authenticated','bl_v39_compat_lab.approval_receipts','INSERT')
 THEN RAISE EXCEPTION 'direct enrollment write exposed'; END IF;
 IF EXISTS(SELECT 1 FROM information_schema.columns
  WHERE table_schema='bl_v39_compat_lab' AND table_name='trust_anchors'
  AND column_name='verified')
 THEN RAISE EXCEPTION 'fixture incorrectly assumes legacy anchor verified'; END IF;
END $test$;
ROLLBACK;
