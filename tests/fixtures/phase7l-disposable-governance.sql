-- Disposable PostgreSQL-only fixture matching Phase7G governance fields used
-- by Phase7L. No live Supabase accounts, signers, keys or messages.
BEGIN;
DO $do$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon')
  THEN CREATE ROLE anon NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated')
  THEN CREATE ROLE authenticated NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='service_role')
  THEN CREATE ROLE service_role NOLOGIN; END IF;
END;
$do$;
CREATE SCHEMA auth;
CREATE TABLE auth.sessions(
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 not_after timestamptz
);
CREATE SCHEMA bl20_first_device_v1_private;
CREATE TABLE bl20_first_device_v1_private.review_intents(
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 session_id uuid NOT NULL REFERENCES auth.sessions(id),
 request_id uuid NOT NULL UNIQUE,
 challenge_id uuid NOT NULL UNIQUE,
 device_id uuid NOT NULL UNIQUE,
 candidate_proof_id uuid NOT NULL UNIQUE,
 reviewer_a uuid NOT NULL,
 reviewer_b uuid NOT NULL,
 issuer_key_sha256 text NOT NULL,
 ecdh_key_sha256 text NOT NULL,
 signing_key_sha256 text NOT NULL,
 reviewed_evidence_sha256 text NOT NULL,
 created_at timestamptz NOT NULL,
 vetoed_at timestamptz,
 state text NOT NULL
);
CREATE TABLE public.messaging_devices(id uuid PRIMARY KEY);

INSERT INTO auth.sessions(id,user_id,not_after)
VALUES(
 '22222222-2222-4222-8222-222222222222',
 '11111111-1111-4111-8111-111111111111',
 pg_catalog.clock_timestamp()+interval '15 minutes');
INSERT INTO bl20_first_device_v1_private.review_intents(
 id,user_id,session_id,request_id,challenge_id,device_id,
 candidate_proof_id,reviewer_a,reviewer_b,issuer_key_sha256,
 ecdh_key_sha256,signing_key_sha256,reviewed_evidence_sha256,
 created_at,state)
VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444',
  '55555555-5555-4555-8555-555555555555',
  '66666666-6666-4666-8666-666666666666',
  '77777777-7777-4777-8777-777777777777',
  '88888888-8888-4888-8888-888888888888',
  repeat('a',64),repeat('b',64),repeat('c',64),repeat('d',64),
  pg_catalog.clock_timestamp()-interval '1 minute',
  'governance_pending_review_only'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '93939393-9393-4939-8939-939393939393',
  '94949494-9494-4949-8949-949494949494',
  '95959595-9595-4959-8959-959595959595',
  '96969696-9696-4969-8969-969696969696',
  '77777777-7777-4777-8777-777777777777',
  '88888888-8888-4888-8888-888888888888',
  repeat('e',64),repeat('f',64),repeat('a',64),repeat('b',64),
  pg_catalog.clock_timestamp()-interval '1 minute',
  'governance_pending_review_only');
COMMIT;
