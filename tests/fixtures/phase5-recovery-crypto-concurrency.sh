#!/usr/bin/env bash
# DISPOSABLE CI Postgres only; never run this against live Supabase.
set -euo pipefail
USER_ID=99999999-9999-4999-8999-999999999999
SESSION=eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
ROW="$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -c "
 SELECT c.id::text,
 encode(extensions.digest(convert_to(ctx.data->>'payload','UTF8'),'sha256'),'hex'),
 encode(extensions.digest(convert_to(ctx.data->>'signatureBase64Url','UTF8'),'sha256'),'hex'),
 (SELECT encode(extensions.digest(convert_to(concat_ws(E'\n',
   i.public_jwk->>'kty',i.public_jwk->>'crv',
   i.public_jwk->>'x',i.public_jwk->>'y'),'UTF8'),'sha256'),'hex')
   FROM bl20_recovery_v1_private.cases r
   JOIN bl20_recovery_v1_private.issuers i ON i.issuer_id=r.issuer_id
   WHERE r.challenge_id=c.id)
 FROM bl20_recovery_v1_private.challenges c,
 LATERAL (SELECT public.bl20_recovery_v1_review_context(c.user_id,c.session_id,c.id) data) ctx
 WHERE c.user_id='$USER_ID'::uuid AND c.state='pending'
 LIMIT 1;")"
test -n "$ROW"
IFS='|' read -r CHALLENGE PAYLOAD_HASH SIGNATURE_HASH ISSUER_KEY_HASH <<< "$ROW"
test "$(printf %s "$PAYLOAD_HASH" | wc -c)" -eq 64
test "$(printf %s "$SIGNATURE_HASH" | wc -c)" -eq 64
test "$(printf %s "$ISSUER_KEY_HASH" | wc -c)" -eq 64
CALL="SELECT public.bl20_recovery_v1_review_consume_v2('$USER_ID'::uuid,'$SESSION'::uuid,'$CHALLENGE'::uuid,'$PAYLOAD_HASH','$SIGNATURE_HASH','$ISSUER_KEY_HASH');"
set +e
psql -X -v ON_ERROR_STOP=1 -c "$CALL" > /tmp/recovery-concurrent-1.log 2>&1 &
P1=$!
psql -X -v ON_ERROR_STOP=1 -c "$CALL" > /tmp/recovery-concurrent-2.log 2>&1 &
P2=$!
wait "$P1"; R1=$?
wait "$P2"; R2=$?
set -e
if [[ "$R1" -eq 0 && "$R2" -ne 0 ]] || [[ "$R2" -eq 0 && "$R1" -ne 0 ]]; then
  echo 'PASS: concurrent recovery receipt accepted exactly once'
else
  cat /tmp/recovery-concurrent-1.log /tmp/recovery-concurrent-2.log
  echo "FAIL: expected one success and one denial (got $R1, $R2)" >&2
  exit 1
fi
psql -X -v ON_ERROR_STOP=1 -c "
DO \$verify\$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n FROM bl20_recovery_v1_private.receipts
 WHERE challenge_id='$CHALLENGE'::uuid;
 IF n<>1 THEN RAISE EXCEPTION 'Expected one receipt, got %',n; END IF;
 IF (SELECT state FROM bl20_recovery_v1_private.challenges WHERE id='$CHALLENGE'::uuid)<>'review_consumed'
 OR (SELECT consumed_at FROM bl20_recovery_v1_private.challenges WHERE id='$CHALLENGE'::uuid) IS NULL
 THEN RAISE EXCEPTION 'Challenge not marked consumed'; END IF;
 IF (SELECT count(*) FROM public.messaging_devices)<>1
 OR (SELECT count(*) FROM public.messaging_device_signing_keys)<>1
 OR EXISTS(SELECT 1 FROM public.messaging_devices WHERE id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid)
 THEN RAISE EXCEPTION 'Unauthorized device escalation'; END IF;
 IF EXISTS(SELECT 1 FROM bl20_recovery_v1_private.receipts WHERE state<>'review_receipt_only')
 THEN RAISE EXCEPTION 'Unauthorized trust state'; END IF;
 IF public.bl20_recovery_v1_review_context('$USER_ID'::uuid,'$SESSION'::uuid,'$CHALLENGE'::uuid) IS NOT NULL
 THEN RAISE EXCEPTION 'Replay challenge context accessible'; END IF;
 RAISE NOTICE 'PASS: one receipt, single-use, no device or signer created';
END \$verify\$;"
# A literal replay must error, not return a successful receipt.
if psql -X -v ON_ERROR_STOP=1 -c "$CALL" >/tmp/recovery-replay.log 2>&1; then
  echo 'FAIL: consumed challenge replay accepted' >&2;exit 1
fi
echo 'PASS: consumed review receipt replay denied'
