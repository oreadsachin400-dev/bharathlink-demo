-- BHARATHLINK VERIFIED DIRECTORY / REVIEW ONLY / NOT A DEPLOY MIGRATION
-- Derived from read-only official TEST schema snapshot 2026-11-12.
-- Creates an opt-in, default-EXECUTE-denied candidate API; do NOT run on
-- active TEST/PROD or grant it until verification authority and all routes
-- have passed independent review. CREATE+REVOKE in one transaction.
BEGIN;

CREATE OR REPLACE FUNCTION public.search_verified_directory(
  p_query text,
  p_limit integer DEFAULT 25
)
RETURNS TABLE (
  entity_id uuid,
  entity_type text,
  legal_name text,
  display_name text,
  business_size text,
  branch_name text,
  jurisdiction text,
  verification_status text,
  verification_method text,
  match_type text,
  matched_endpoint_type text,
  matched_endpoint_display_value text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $bhl_dir$
DECLARE
  v_me uuid := (SELECT auth.uid());
  v_query text := pg_catalog.btrim(coalesce(p_query,''));
  v_phone_like boolean;
  v_phone text;
  v_now timestamptz := pg_catalog.now();
  v_claims bigint;
  v_pattern text;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'Directory search requires sign-in' USING ERRCODE='42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 25 THEN
    RAISE EXCEPTION 'Invalid directory limit' USING ERRCODE='22023';
  END IF;
  IF length(v_query) NOT BETWEEN 2 AND 120 OR
     v_query ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'Invalid directory query' USING ERRCODE='22023';
  END IF;

  -- Phone queries never fall back to partial organisation-name matches.
  -- Mobile endpoint verification is exact-only; no last digits, prefix or
  -- substring lookup that could leak third-party contact information.
  v_phone_like := v_query ~ '^[0-9+().[:space:]-]+$';
  IF v_phone_like THEN
    v_phone := public.normalize_entity_endpoint('mobile',v_query);
    -- Version 1 supports Indian 10-digit mobile endpoints, with
    -- optional +91 country code handled by the existing normalizer.
    IF v_phone !~ '^[6-9][0-9]{9}$' THEN
      RETURN;
    END IF;

    SELECT count(DISTINCT e.id) INTO v_claims
    FROM public.entity_profiles e
    JOIN public.entity_endpoints ep ON ep.entity_id=e.id
    WHERE e.country_code='IN'
      AND e.verification_status='verified'
      AND e.verified_at IS NOT NULL AND e.verified_at<=v_now
      AND (e.verification_expires_at IS NULL OR e.verification_expires_at>v_now)
      AND ep.endpoint_type='mobile'
      AND ep.verification_status='verified'
      AND ep.verified_at IS NOT NULL AND ep.verified_at<=v_now
      AND (ep.verification_expires_at IS NULL OR ep.verification_expires_at>v_now)
      AND ep.revoked_at IS NULL
      AND public.normalize_entity_endpoint('mobile',ep.endpoint_value)=v_phone
      AND (
        NOT EXISTS (SELECT 1 FROM public.entity_contact_point_endpoints map
                    WHERE map.endpoint_id=ep.id)
        OR EXISTS (
          SELECT 1 FROM public.entity_contact_point_endpoints map
          JOIN public.entity_contact_points cp ON cp.id=map.contact_point_id
          WHERE map.endpoint_id=ep.id AND cp.entity_id=e.id AND cp.active=true
        )
      );

    IF v_claims>1 THEN
      -- Never label a contested endpoint as belonging to either entity.
      RAISE EXCEPTION 'Conflicting verified endpoint ownership: manual review needed'
        USING ERRCODE='P0001';
    END IF;

    RETURN QUERY
    SELECT e.id,e.entity_type,e.legal_name,e.display_name,
           e.business_size,e.branch_name,e.jurisdiction,
           e.verification_status,e.verification_method,
           'exact_endpoint'::text,ep.endpoint_type,ep.display_value
    FROM public.entity_profiles e
    JOIN public.entity_endpoints ep ON ep.entity_id=e.id
    WHERE v_claims=1
      AND e.country_code='IN'
      AND e.verification_status='verified'
      AND e.verified_at IS NOT NULL AND e.verified_at<=v_now
      AND (e.verification_expires_at IS NULL OR e.verification_expires_at>v_now)
      AND ep.endpoint_type='mobile'
      AND ep.verification_status='verified'
      AND ep.verified_at IS NOT NULL AND ep.verified_at<=v_now
      AND (ep.verification_expires_at IS NULL OR ep.verification_expires_at>v_now)
      AND ep.revoked_at IS NULL
      AND public.normalize_entity_endpoint('mobile',ep.endpoint_value)=v_phone
      AND (
        NOT EXISTS (SELECT 1 FROM public.entity_contact_point_endpoints map
                    WHERE map.endpoint_id=ep.id)
        OR EXISTS (
          SELECT 1 FROM public.entity_contact_point_endpoints map
          JOIN public.entity_contact_points cp ON cp.id=map.contact_point_id
          WHERE map.endpoint_id=ep.id AND cp.entity_id=e.id AND cp.active=true
        )
      )
    ORDER BY ep.verified_at DESC,ep.id
    LIMIT 1;
    RETURN;
  END IF;

  -- Escape SQL wildcard operators in user input before ILIKE; these
  -- are organisation/department name searches, not partial mobile
  -- endpoint lookups. Never return an endpoint on fuzzy name match.
  v_pattern := '%' ||
    pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(
      v_query, E'\\', E'\\\\'), '%', E'\\%'), '_', E'\\_') || '%';

  RETURN QUERY
  SELECT e.id,e.entity_type,e.legal_name,e.display_name,
         e.business_size,e.branch_name,e.jurisdiction,
         e.verification_status,e.verification_method,
         'entity_name'::text,NULL::text,NULL::text
  FROM public.entity_profiles e
  WHERE e.verification_status='verified'
    AND e.verified_at IS NOT NULL AND e.verified_at<=v_now
    AND (e.verification_expires_at IS NULL OR e.verification_expires_at>v_now)
    AND (
      e.legal_name ILIKE v_pattern ESCAPE E'\\'
      OR e.display_name ILIKE v_pattern ESCAPE E'\\'
      OR e.jurisdiction ILIKE v_pattern ESCAPE E'\\'
      OR e.branch_name ILIKE v_pattern ESCAPE E'\\'
    )
  ORDER BY
    CASE WHEN pg_catalog.lower(e.legal_name)=pg_catalog.lower(v_query)
      OR pg_catalog.lower(COALESCE(e.display_name,''))=pg_catalog.lower(v_query)
      THEN 0 ELSE 1 END,
    e.legal_name,e.id
  LIMIT p_limit;
END;
$bhl_dir$;

REVOKE ALL ON FUNCTION public.search_verified_directory(text,integer)
  FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
