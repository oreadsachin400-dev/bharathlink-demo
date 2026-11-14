\set ON_ERROR_STOP on
\echo 'VERIFIED DIRECTORY QUOTA: synthetic users/numbers, disposable PG16 only'

SET ROLE anon;
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Anonymous quota-wrapped search accessible'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Unreleased quota-wrapped search accessible'; END IF;
 blocked:=false;
 BEGIN
  PERFORM 1 FROM bl_directory_lab.directory_search_quota;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Quota table readable by app user'; END IF;
 blocked:=false;
 BEGIN
  PERFORM public.search_verified_directory('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Underlying unthrottled search callable'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Raw search, quota table and wrapper all denied until isolated GRANT.'

GRANT EXECUTE ON FUNCTION public.search_verified_directory_guarded_v1(
 text,integer
) TO authenticated;

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $cap$
DECLARE i integer;found_count integer;blocked boolean:=false;
BEGIN
 FOR i IN 1..5 LOOP
  SELECT count(*)::integer INTO found_count
  FROM public.search_verified_directory_guarded_v1('9210987654',25);
  IF found_count<>1 THEN
   RAISE EXCEPTION 'Valid exact verified lookup failed before quota reached';
  END IF;
 END LOOP;
 BEGIN
  PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Sixth account search bypassed per-minute cap'; END IF;
END $cap$;
RESET ROLE;
DO $check$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM bl_directory_lab.directory_search_quota
  WHERE user_id='11111111-1111-4111-8111-111111111111'
   AND window_seconds=60 AND used=5
 ) THEN RAISE EXCEPTION 'Atomic minute quota did not stop at 5'; END IF;
 IF NOT EXISTS (
  SELECT 1 FROM bl_directory_lab.directory_search_quota
  WHERE user_id='11111111-1111-4111-8111-111111111111'
   AND window_seconds=86400 AND used=5
 ) THEN RAISE EXCEPTION 'Denied request incorrectly changed day counter'; END IF;
END $check$;
\echo 'PASS: Exact searches stop after 5/min/account; rejected request does not consume daily quota.'

SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $isolation$
DECLARE n integer;
BEGIN
 SELECT count(*)::integer INTO n
 FROM public.search_verified_directory_guarded_v1('9210987654',25);
 IF n<>1 THEN RAISE EXCEPTION 'Other account was blocked by first account quota'; END IF;
END $isolation$;
RESET ROLE;
\echo 'PASS: A different account has a separate, isolated search quota.'

-- A full daily bucket must reject even if the minute count is currently 0.
-- This test writes synthetic quota records only as local PG16 postgres.
INSERT INTO bl_directory_lab.directory_search_quota
(user_id,window_seconds,window_bucket,used)
VALUES(
 '33333333-3333-4333-8333-333333333333',86400,
 floor(extract(epoch from clock_timestamp())/86400)::bigint,50
);
SET ROLE authenticated;
SET request.jwt.claim.sub='33333333-3333-4333-8333-333333333333';
DO $daily$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Daily quota of 50 exceeded'; END IF;
END $daily$;
RESET ROLE;
DO $rollback$
BEGIN
 IF EXISTS (
  SELECT 1 FROM bl_directory_lab.directory_search_quota
  WHERE user_id='33333333-3333-4333-8333-333333333333'
    AND window_seconds=60
 ) THEN RAISE EXCEPTION 'Minute increment was committed despite daily denial'; END IF;
END $rollback$;
\echo 'PASS: 50/day cap enforced and minute counter rolled back if day limit rejected.'

SET ROLE authenticated;
RESET request.jwt.claim.sub;
DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Missing auth account accepted'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Unauthenticated request does not get a search quota identity.'

-- No client grants left after single-connection regression suite.
REVOKE EXECUTE ON FUNCTION public.search_verified_directory_guarded_v1(
 text,integer
) FROM authenticated;
DO $check$
BEGIN
 IF has_function_privilege('authenticated',
 'public.search_verified_directory_guarded_v1(text,integer)','EXECUTE')
 OR has_function_privilege('authenticated',
 'public.search_verified_directory(text,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'Unthrottled/direct search accidentally enabled'; END IF;
END $check$;
\echo 'PASS: Both guarded and underlying raw directory RPCs remain unavailable.'
