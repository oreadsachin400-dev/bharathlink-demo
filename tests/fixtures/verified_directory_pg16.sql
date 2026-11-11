-- DISPOSABLE PostgreSQL 16 ONLY. Synthetic legal names & numbers.
-- Schema types grounded in official TEST metadata, intentionally simplified.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $uid$
 SELECT nullif(pg_catalog.current_setting('request.jwt.claim.sub',true),'')::uuid
$uid$;
GRANT USAGE ON SCHEMA auth,public TO anon,authenticated;
CREATE TABLE public.entity_profiles(
 id uuid PRIMARY KEY,
 entity_type text NOT NULL CHECK(entity_type IN
  ('government_department','police','hospital','business','public_utility')),
 legal_name text NOT NULL,
 display_name text,
 business_size text,
 branch_name text,
 jurisdiction text,
 country_code text NOT NULL DEFAULT 'IN',
 verification_status text NOT NULL DEFAULT 'pending' CHECK(
  verification_status IN ('pending','verified','suspended','revoked','rejected')),
 verification_method text,
 verified_at timestamptz,
 verification_expires_at timestamptz
);
CREATE TABLE public.entity_endpoints(
 id uuid PRIMARY KEY,
 entity_id uuid NOT NULL REFERENCES public.entity_profiles(id),
 endpoint_type text NOT NULL CHECK(endpoint_type IN
  ('mobile','messaging','bharatmail','upi','email','website')),
 endpoint_value text NOT NULL,
 display_value text NOT NULL,
 verification_status text NOT NULL DEFAULT 'pending' CHECK(
  verification_status IN ('pending','verified','suspended','revoked','rejected')),
 verified_at timestamptz,
 verification_expires_at timestamptz,
 revoked_at timestamptz
);
CREATE TABLE public.entity_contact_points(
 id uuid PRIMARY KEY,
 entity_id uuid NOT NULL REFERENCES public.entity_profiles(id),
 active boolean NOT NULL DEFAULT true
);
CREATE TABLE public.entity_contact_point_endpoints(
 contact_point_id uuid NOT NULL REFERENCES public.entity_contact_points(id),
 endpoint_id uuid NOT NULL REFERENCES public.entity_endpoints(id),
 PRIMARY KEY(contact_point_id,endpoint_id)
);
ALTER TABLE public.entity_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_contact_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_contact_point_endpoints ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA public
 FROM PUBLIC,anon,authenticated,service_role;
-- Existing official TEST endpoint normalizer copied from read-only
-- pg_get_functiondef, not re-created from assumption.

CREATE OR REPLACE FUNCTION public.normalize_entity_endpoint(p_type text, p_value text)
 RETURNS text
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
DECLARE
  v_type text := lower(trim(coalesce(p_type, '')));
  v text := trim(coalesce(p_value, ''));
BEGIN
  IF v_type = 'mobile' THEN
    v := regexp_replace(v, '[^0-9]', '', 'g');

    IF length(v) = 12
       AND left(v, 2) = '91' THEN
      v := right(v, 10);
    END IF;

    RETURN v;
  END IF;

  IF v_type IN (
    'messaging',
    'bharatmail',
    'upi',
    'email',
    'website'
  ) THEN
    RETURN lower(v);
  END IF;

  RETURN lower(v);
END;
$function$
;
