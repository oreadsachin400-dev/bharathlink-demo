#!/usr/bin/env bash
set -euo pipefail

# HERMETIC ONLY: never run this against a real Supabase project.
if [[ "$BHL_ISOLATED_PG_ONLY" != "1" ||
      "$PGHOST" != "127.0.0.1" ||
      "$PGDATABASE" != "bharathlink_isolated" ||
      "$PGUSER" != "postgres" ]]; then
  echo "REFUSED: requires disposable PostgreSQL CI database" >&2
  exit 2
fi

dir="$(mktemp -d)"
cleanup(){
  psql -X -v ON_ERROR_STOP=1 -qAtc \
    "REVOKE EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid) FROM authenticated;" >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT
psql -X -v ON_ERROR_STOP=1 -qAtc \
  "GRANT EXECUTE ON FUNCTION public.claim_protected_wrapped_key_v1(uuid,uuid) TO authenticated;" >/dev/null

# Two concurrent real PostgreSQL sessions, two separate verified recipient
# devices and one View Once row. First holds the transaction open after
# claiming; second must block on same row and then be denied.
PGAPPNAME=bhl_claim_first psql -X -v ON_ERROR_STOP=1 >"$dir/first.log" 2>&1 <<'SQL' &
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
BEGIN;
SELECT public.claim_protected_wrapped_key_v1(
 'f0000000-0000-4000-8000-000000000006',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb') AS winning_key;
\echo FIRST_KEY_RETURNED
SELECT pg_sleep(4);
COMMIT;
SQL
first=$!

ready=0
for _ in $(seq 1 80); do
  state="$(psql -X -v ON_ERROR_STOP=1 -tAc \
    "SELECT count(*) FROM pg_catalog.pg_stat_activity
     WHERE application_name='bhl_claim_first' AND state='active'
       AND query LIKE '%pg_sleep(4)%';" | tr -d '[:space:]')"
  if [[ "$state" == "1" ]]; then ready=1; break; fi
  if ! kill -0 "$first" 2>/dev/null; then break; fi
  sleep .05
done
if [[ "$ready" != "1" ]]; then
  echo "FAIL: first claim did not enter post-claim transaction hold" >&2
  cat "$dir/first.log" >&2
  wait "$first" || true
  exit 1
fi

PGAPPNAME=bhl_claim_second psql -X -v ON_ERROR_STOP=1 >"$dir/second.log" 2>&1 <<'SQL' &
SET ROLE authenticated;
SET request.jwt.claim.sub='22222222-2222-4222-8222-222222222222';
DO $second$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
   PERFORM public.claim_protected_wrapped_key_v1(
     'f0000000-0000-4000-8000-000000000006',
     'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Concurrent second device received a wrapped key'; END IF;
 RAISE NOTICE 'SECOND_DEVICE_DENIED_AFTER_RACE';
END $second$;
SQL
second=$!

blocked=0
for _ in $(seq 1 65); do
  waiting="$(psql -X -v ON_ERROR_STOP=1 -tAc \
    "SELECT count(*) FROM pg_catalog.pg_stat_activity
     WHERE application_name='bhl_claim_second'
       AND wait_event_type='Lock';" | tr -d '[:space:]')"
  if [[ "$waiting" == "1" ]]; then blocked=1; break; fi
  if ! kill -0 "$second" 2>/dev/null; then break; fi
  sleep .05
done

wait "$first"
wait "$second"
grep -q 'race-device-1' "$dir/first.log" ||
  { echo "FAIL: winner did not get expected wrapped key" >&2; cat "$dir/first.log" >&2; exit 1; }
grep -q 'SECOND_DEVICE_DENIED_AFTER_RACE' "$dir/second.log" ||
  { echo "FAIL: second device was not explicitly denied" >&2; cat "$dir/second.log" >&2; exit 1; }
if [[ "$blocked" != "1" ]]; then
  echo "FAIL: did not observe second claim blocked on first transaction" >&2
  exit 1
fi

psql -X -v ON_ERROR_STOP=1 -qAt <<'SQL'
DO $check$
BEGIN
 IF (SELECT consumed_device_id FROM public.view_once_messages
 WHERE message_id='f0000000-0000-4000-8000-000000000006')
   IS DISTINCT FROM 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid THEN
  RAISE EXCEPTION 'Wrong View Once winner';
 END IF;
 IF EXISTS (SELECT 1 FROM bl_protected_lab.wrapped_keys
 WHERE message_id='f0000000-0000-4000-8000-000000000006') THEN
  RAISE EXCEPTION 'Losing-device envelope survived';
 END IF;
END $check$;
SQL
echo 'PASS: Two concurrent device sessions; observed database lock wait, first claim wins, second replay denied and vault emptied.'
