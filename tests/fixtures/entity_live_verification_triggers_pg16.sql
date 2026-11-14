-- DISPOSABLE PostgreSQL 16 ONLY. Not an active TEST/PROD migration.
-- Source: official BharathLink-20 TEST Supabase read-only pg_get_functiondef()
-- and pg_get_triggerdef() snapshot on 14 Nov 2026.
-- Mirrors exactly three verification/claim trigger bodies, but NOT the
-- complete production schema, RLS, privileges, or auth runtime.
-- The auth.role stub below is ONLY a GUC fixture for trigger-compat testing.
-- NEVER replace Supabase auth.role() or install this file in a live project.
BEGIN;
CREATE FUNCTION auth.role() RETURNS text
  LANGUAGE sql STABLE SET search_path TO ''
  AS $role$ SELECT nullif(
    pg_catalog.current_setting('request.jwt.claim.role',true),'') $role$;
ALTER TABLE public.entity_profiles
 ADD COLUMN updated_at timestamptz NOT NULL DEFAULT pg_catalog.now();
ALTER TABLE public.entity_endpoints
 ADD COLUMN updated_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
 ADD COLUMN verification_method text,
 ADD COLUMN revoked_by uuid,
 ADD COLUMN revocation_reason text;

-- Official TEST trigger: protect_entity_verification_fields
CREATE OR REPLACE FUNCTION public.protect_entity_verification_fields()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
BEGIN
  IF COALESCE(auth.role(), '')
     IN ('anon', 'authenticated')
  THEN
    IF NEW.verification_status
         IS DISTINCT FROM OLD.verification_status
       OR NEW.verification_method
         IS DISTINCT FROM OLD.verification_method
       OR NEW.verified_at
         IS DISTINCT FROM OLD.verified_at
       OR NEW.verification_expires_at
         IS DISTINCT FROM OLD.verification_expires_at
    THEN
      RAISE EXCEPTION
        'Entity verification fields are server-authoritative';
    END IF;
  END IF;

  NEW.updated_at := now();

  RETURN NEW;
END;
$function$;
CREATE TRIGGER protect_entity_verification_fields BEFORE UPDATE ON entity_profiles FOR EACH ROW EXECUTE FUNCTION protect_entity_verification_fields();

-- Official TEST trigger: protect_entity_endpoint_verification_fields
CREATE OR REPLACE FUNCTION public.protect_entity_endpoint_verification_fields()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
BEGIN
  IF auth.role() IN ('anon', 'authenticated') THEN
    IF NEW.verification_status
         IS DISTINCT FROM OLD.verification_status
       OR NEW.verification_method
         IS DISTINCT FROM OLD.verification_method
       OR NEW.verified_at
         IS DISTINCT FROM OLD.verified_at
       OR NEW.verification_expires_at
         IS DISTINCT FROM OLD.verification_expires_at
       OR NEW.revoked_at
         IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_by
         IS DISTINCT FROM OLD.revoked_by
    THEN
      RAISE EXCEPTION
        'Endpoint verification fields are server-authoritative';
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$function$;
CREATE TRIGGER protect_entity_endpoint_verification_fields BEFORE UPDATE ON entity_endpoints FOR EACH ROW EXECUTE FUNCTION protect_entity_endpoint_verification_fields();

-- Official TEST trigger: trg_prevent_cross_entity_endpoint_claim
CREATE OR REPLACE FUNCTION public.prevent_cross_entity_endpoint_claim()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_normalized text;
BEGIN
  v_normalized :=
    public.normalize_entity_endpoint(
      NEW.endpoint_type,
      NEW.endpoint_value
    );

  IF v_normalized IS NULL
     OR trim(v_normalized) = '' THEN
    RAISE EXCEPTION 'Invalid official endpoint';
  END IF;

  NEW.endpoint_value := v_normalized;

  IF EXISTS (
    SELECT 1
    FROM public.entity_endpoints ee
    WHERE ee.entity_id <> NEW.entity_id
      AND ee.endpoint_type = NEW.endpoint_type
      AND ee.verification_status IN ('verified', 'suspended')
      AND public.normalize_entity_endpoint(
        ee.endpoint_type,
        ee.endpoint_value
      ) = v_normalized
      AND (
        TG_OP = 'INSERT'
        OR ee.id <> NEW.id
      )
  ) THEN
    RAISE EXCEPTION
      'Endpoint already verified or reserved for another organisation';
  END IF;

  RETURN NEW;
END;
$function$;
CREATE TRIGGER trg_prevent_cross_entity_endpoint_claim BEFORE INSERT OR UPDATE ON entity_endpoints FOR EACH ROW EXECUTE FUNCTION prevent_cross_entity_endpoint_claim();

COMMIT;
