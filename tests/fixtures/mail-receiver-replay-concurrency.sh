#!/usr/bin/env bash
# CI only: synthetic PostgreSQL 17 race across multiple independent psql processes.
set -euo pipefail
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# One nonce + one exact provider/receipt across twelve independent processes.
seq 1 12 | xargs -P 8 -I{} bash -c '
  psql -XAt -v ON_ERROR_STOP=1 -c "
    select public.bl_mail_consume_receiver_test_v1(
      '\''test-pin-b'\'',
      '\''11111111-1111-4111-8111-111111111111'\''::uuid,
      '\''synthetic-race-one'\'',repeat('\''a'\'',64),repeat('\''b'\'',64),
      (select at_time from public.bl_mail_receiver_test_race_stamp_v1));
  "
' > "$out/idempotent.log"

first="$(grep -c '^recorded$' "$out/idempotent.log" || true)"
dups="$(grep -c '^duplicate$' "$out/idempotent.log" || true)"
[[ "$first" -eq 1 && "$dups" -eq 11 ]] || {
  cat "$out/idempotent.log"
  echo "ERROR: concurrent idempotent consumption: first=$first duplicates=$dups"
  exit 1
}

# One nonce reused for twelve different providers: exactly one can be stored;
# other eleven must be explicitly rejected, not silently accepted or retried.
seq 1 12 | xargs -P 8 -I{} bash -c '
  psql -XAt -v ON_ERROR_STOP=1 -c "
    select public.bl_mail_consume_receiver_test_v1(
      '\''test-pin-b'\'',
      '\''22222222-2222-4222-8222-222222222222'\''::uuid,
      '\''synthetic-conflict-{}'\'',repeat('\''c'\'',64),repeat('\''d'\'',64),
      (select at_time from public.bl_mail_receiver_test_race_stamp_v1));
  "
' > "$out/conflict.log"

first2="$(grep -c '^recorded$' "$out/conflict.log" || true)"
denied="$(grep -c '^replay_or_conflict$' "$out/conflict.log" || true)"
[[ "$first2" -eq 1 && "$denied" -eq 11 ]] || {
  cat "$out/conflict.log"
  echo "ERROR: concurrent nonce replay: first=$first2 denied=$denied"
  exit 1
}

psql -XAt -v ON_ERROR_STOP=1 -c "
do \$\$
declare n integer; r text;
begin
 select count(*) into n from public.bl_mail_receiver_consumed_test_v1;
 if n<>4 then raise exception 'race consumed unexpected rows: %', n; end if;
 r=public.bl_mail_revoke_receiver_test_v1('test-pin-b','synthetic rotation after race');
 if r<>'revoked' then raise exception 'could not revoke second key: %', r; end if;
 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-b','33333333-3333-4333-8333-333333333333'::uuid,
  'synthetic-after-revoke',repeat('a',64),repeat('b',64),now());
 if r<>'revoked_key' then raise exception 'post-revoke race accepted: %',r; end if;
end
\$\$;
"

echo "PASS: across 24 independent concurrent psql calls:"
echo " - exact receipt: one recorded, 11 duplicate"
echo " - nonce replay against other providers: one recorded, 11 rejected"
echo " - revoked receiver key: all future receipts denied"
