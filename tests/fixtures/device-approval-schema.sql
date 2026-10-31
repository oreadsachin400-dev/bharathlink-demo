-- Synthetic-only PostgreSQL schema used by CI. No live Supabase rows touched.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
CREATE SCHEMA auth;
CREATE SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
CREATE TABLE auth.users(id uuid PRIMARY KEY);
CREATE TABLE public.messaging_devices(
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth.users(id),
  public_key_jwk jsonb NOT NULL, key_algorithm text NOT NULL,
  device_label text, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.messaging_device_signing_keys(
  device_id uuid PRIMARY KEY REFERENCES public.messaging_devices(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  signing_public_key_jwk jsonb NOT NULL,
  verified_at timestamptz NOT NULL,
  verification_method text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.messaging_device_enrollment_requests(
 request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES auth.users(id),
 proposed_device_id uuid NOT NULL,
 proposed_public_key_jwk jsonb NOT NULL,
 proposed_key_algorithm text NOT NULL DEFAULT 'ECDH-P256',
 device_label text,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT (now()+interval '10 minutes'),
 status text NOT NULL DEFAULT 'pending',
 approved_by_device_id uuid REFERENCES public.messaging_devices(id),
 consumed_at timestamptz,
 challenge_id uuid NOT NULL DEFAULT gen_random_uuid(),
 proposed_signing_public_key_jwk jsonb,
 approval_protocol_version integer NOT NULL DEFAULT 1
);
ALTER TABLE public.messaging_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY messaging_devices_insert_trusted_approval_only
 ON public.messaging_devices FOR INSERT TO authenticated WITH CHECK (false);
INSERT INTO auth.users(id) VALUES
 ('11111111-1111-4111-8111-111111111111'),
 ('99999999-9999-4999-8999-999999999999');
INSERT INTO public.messaging_devices(id,user_id,public_key_jwk,key_algorithm,device_label)
 VALUES ('22222222-2222-4222-8222-222222222222',
         '11111111-1111-4111-8111-111111111111',
         '{"kty":"EC","crv":"P-256"}','ECDH-P256','Trusted mock phone');
INSERT INTO public.messaging_device_signing_keys(
 device_id,user_id,signing_public_key_jwk,verified_at,verification_method)
 VALUES ('22222222-2222-4222-8222-222222222222',
         '11111111-1111-4111-8111-111111111111',
         jsonb_build_object('kty','EC','crv','P-256','x',repeat('a',43),'y',repeat('b',43)),
         now()-interval '1 day','trusted_device_signature');
INSERT INTO public.messaging_device_enrollment_requests(
 request_id,user_id,proposed_device_id,proposed_public_key_jwk,proposed_key_algorithm,
 proposed_signing_public_key_jwk,device_label)
 VALUES ('33333333-3333-4333-8333-333333333333',
         '11111111-1111-4111-8111-111111111111',
         '44444444-4444-4444-8444-444444444444',
         jsonb_build_object('kty','EC','crv','P-256','x',repeat('c',43),'y',repeat('d',43)),
         'ECDH-P256',
         jsonb_build_object('kty','EC','crv','P-256','x',repeat('e',43),'y',repeat('f',43)),
         'Synthetic new phone');
INSERT INTO public.messaging_device_enrollment_requests(
 request_id,user_id,proposed_device_id,proposed_public_key_jwk,proposed_signing_public_key_jwk)
 VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
         '99999999-9999-4999-8999-999999999999',
         'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
         jsonb_build_object('kty','EC','crv','P-256','x',repeat('g',43),'y',repeat('h',43)),
         jsonb_build_object('kty','EC','crv','P-256','x',repeat('i',43),'y',repeat('j',43)));
