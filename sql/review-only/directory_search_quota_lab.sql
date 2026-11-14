-- BHARATHLINK VERIFIED DIRECTORY ACCOUNT-QUOTA / REVIEW ONLY
-- Disposable PG16 proof, NOT a production-ready abuse defense.
-- This protects the *only future exposed search route*; underlying
-- search_verified_directory(text,integer) MUST stay EXECUTE denied to
-- anon/authenticated (otherwise callers bypass quota).
-- A real deployment also needs edge IP/device controls, evidence policy,
-- bot defense and authoritative onboarding. Never enable based on CI alone.
BEGIN;

CREATE SCHEMA IF NOT EXISTS bl_directory_lab;
REVOKE ALL ON SCHEMA bl_directory_lab
  FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl_directory_lab.directory_search_quota (
  user_id uuid NOT NULL,
  window_seconds integer NOT NULL CHECK (window_seconds IN (60,86400)),
  window_bucket bigint NOT NULL,
  used integer NOT NULL CHECK (used BETWEEN 1 AND 100),
  PRIMARY KEY(user_id,window_seconds,window_bucket)
);
ALTER TABLE bl_directory_lab.directory_search_quota ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE bl_directory_lab.directory_search_quota
  FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.search_verified_directory_guarded_v1(
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
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $quota_search$
DECLARE
  v_uid uuid := (SELECT auth.uid());
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_minute_bucket bigint := pg_catalog.floor(
    extract(epoch from v_now)/60
  )::bigint;
  v_day_bucket bigint := pg_catalog.floor(
    extract(epoch from v_now)/86400
  )::bigint;
  v_used integer;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Directory search unavailable' USING ERRCODE='42501';
  END IF;

  -- Conservative trial limits: 5 lookups/min/account, 50/day/account.
  -- ON CONFLICT row locking serializes competing searches; if daily limit
  -- rejects, the preceding minute increment rolls back transactionally.
  INSERT INTO bl_directory_lab.directory_search_quota AS q(
    user_id,window_seconds,window_bucket,used
  ) VALUES(v_uid,60,v_minute_bucket,1)
  ON CONFLICT(user_id,window_seconds,window_bucket)
  DO UPDATE SET used=q.used+1 WHERE q.used<5
  RETURNING used INTO v_used;
  IF v_used IS NULL THEN
    RAISE EXCEPTION 'Directory search quota exceeded' USING ERRCODE='42501';
  END IF;

  v_used := NULL;
  INSERT INTO bl_directory_lab.directory_search_quota AS q(
    user_id,window_seconds,window_bucket,used
  ) VALUES(v_uid,86400,v_day_bucket,1)
  ON CONFLICT(user_id,window_seconds,window_bucket)
  DO UPDATE SET used=q.used+1 WHERE q.used<50
  RETURNING used INTO v_used;
  IF v_used IS NULL THEN
    RAISE EXCEPTION 'Directory search quota exceeded' USING ERRCODE='42501';
  END IF;

  -- The underlying search function is deliberately NOT client callable.
  -- It checks exact verified/current endpoints, handles ambiguity and
  -- authenticates; this wrapper adds per-account budget atomically.
  RETURN QUERY
  SELECT x.entity_id,x.entity_type,x.legal_name,x.display_name,
    x.business_size,x.branch_name,x.jurisdiction,x.verification_status,
    x.verification_method,x.match_type,x.matched_endpoint_type,
    x.matched_endpoint_display_value
  FROM public.search_verified_directory(p_query,p_limit) x;
END;
$quota_search$;

REVOKE ALL ON FUNCTION public.search_verified_directory_guarded_v1(
 text,integer
) FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
