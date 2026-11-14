#!/usr/bin/env bash
set -euo pipefail
# Hermetic concurrency test. Never permit a remote/live Supabase DB.
if [[ "$BHL_ISOLATED_PG_ONLY" != "1" ||
      "$PGHOST" != "127.0.0.1" ||
      "$PGDATABASE" != "bharathlink_verified_directory_lab" ||
      "$PGUSER" != "postgres" ]]; then
  echo 'REFUSED: must target disposable localhost PG16 fixture' >&2
  exit 2
fi
dir="$(mktemp -d)"
cleanup(){
  psql -X -v ON_ERROR_STOP=1 -qAtc \
    "REVOKE EXECUTE ON FUNCTION public.search_verified_directory_guarded_v1(text,integer) FROM authenticated;" >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT

# Daily cap is 50, prepare at 49 for the same verified account.
# Minute bucket may turn over during test; day-bucket stays fixed.
psql -X -v ON_ERROR_STOP=1 -qAt <<'SQL'
INSERT INTO bl_directory_lab.directory_search_quota(
 user_id,window_seconds,window_bucket,used
) VALUES (
 '44444444-4444-4444-8444-444444444444',
 86400,floor(extract(epoch from clock_timestamp())/86400)::bigint,49
);
GRANT EXECUTE ON FUNCTION
 public.search_verified_directory_guarded_v1(text,integer)
 TO authenticated;
SQL

PGAPPNAME=directory_first psql -X -v ON_ERROR_STOP=1 >"$dir/first.log" 2>&1 <<'SQL' &
SET ROLE authenticated;
SET request.jwt.claim.sub='44444444-4444-4444-8444-444444444444';
BEGIN;
SELECT count(*) AS first_lookup_found
FROM public.search_verified_directory_guarded_v1('9210987654',25);
\echo FIRST_LOOKUP_SUCCESS
SELECT pg_sleep(4);
COMMIT;
SQL
first=$!

ready=0
for _ in $(seq 1 90); do
  state="$(psql -X -v ON_ERROR_STOP=1 -tAc \
    "SELECT count(*) FROM pg_stat_activity WHERE application_name='directory_first'
     AND state='active' AND query LIKE '%pg_sleep(4)%';" \
    | tr -d '[:space:]')"
  if [[ "$state" == "1" ]]; then ready=1; break; fi
  if ! kill -0 "$first" 2>/dev/null; then break; fi
  sleep .04
done
if [[ "$ready" != "1" ]]; then
  echo 'FAIL: first transaction did not enter hold after quota increment' >&2
  cat "$dir/first.log" >&2
  wait "$first" || true
  exit 1
fi

PGAPPNAME=directory_second psql -X -v ON_ERROR_STOP=1 >"$dir/second.log" 2>&1 <<'SQL' &
SET ROLE authenticated;
SET request.jwt.claim.sub='44444444-4444-4444-8444-444444444444';
DO $denied$
DECLARE blocked boolean:=false;
BEGIN
  BEGIN
    PERFORM public.search_verified_directory_guarded_v1('9210987654',25);
  EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Second concurrent request bypassed account daily quota';
  END IF;
  RAISE NOTICE 'SECOND_SEARCH_RATE_LIMITED';
END $denied$;
SQL
second=$!

blocked=0
for _ in $(seq 1 85); do
  waiting="$(psql -X -v ON_ERROR_STOP=1 -tAc \
    "SELECT count(*) FROM pg_stat_activity
      WHERE application_name='directory_second'
        AND wait_event_type='Lock';" | tr -d '[:space:]')"
  if [[ "$waiting" == "1" ]]; then blocked=1; break; fi
  if ! kill -0 "$second" 2>/dev/null; then break; fi
  sleep .04
done

wait "$first"
wait "$second"
grep -q FIRST_LOOKUP_SUCCESS "$dir/first.log" || {
  cat "$dir/first.log" >&2; echo 'FAIL: winning request failed' >&2; exit 1;
}
grep -q SECOND_SEARCH_RATE_LIMITED "$dir/second.log" || {
  cat "$dir/second.log" >&2; echo 'FAIL: losing request not explicitly denied' >&2; exit 1;
}
if [[ "$blocked" != "1" ]]; then
  echo 'FAIL: did not observe second request waiting on quota-row lock' >&2
  exit 1
fi

psql -X -v ON_ERROR_STOP=1 -qAt <<'SQL'
DO $verify$
BEGIN
 IF (SELECT used FROM bl_directory_lab.directory_search_quota
    WHERE user_id='44444444-4444-4444-8444-444444444444'
    AND window_seconds=86400
    AND window_bucket=floor(extract(epoch from clock_timestamp())/86400)::bigint)
   <> 50 THEN
    RAISE EXCEPTION 'Final daily quota incorrect after two parallel searches';
 END IF;
END $verify$;
SQL
echo 'PASS: Real concurrent PostgreSQL requests: observed lock wait; 49->50 one accepted and second rate-limited.'
