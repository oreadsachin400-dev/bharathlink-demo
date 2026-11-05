-- Phase7L disposable Postgres integration tests (NOT live Supabase).
CREATE FUNCTION pg_temp.stage_evidence(
 p_intent uuid, p_nonce text DEFAULT repeat('7',64),
 p_key_a text DEFAULT repeat('1',64),
 p_expires timestamptz DEFAULT pg_catalog.clock_timestamp()+interval '2 minutes'
) RETURNS jsonb LANGUAGE sql VOLATILE AS $fn$
 SELECT bl20_review_ledger_v1_private.stage_review_evidence(
   p_intent,p_key_a,repeat('2',64),
   repeat('3',64),repeat('4',64),
   repeat('5',64),repeat('6',64),
   p_nonce,p_expires);
$fn$;

DO $test$
DECLARE
 a uuid:='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 b uuid:='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
 reply jsonb;
 blocked boolean;
BEGIN
 IF has_schema_privilege('anon','bl20_review_ledger_v1_private','USAGE')
 OR has_schema_privilege('authenticated','bl20_review_ledger_v1_private','USAGE')
 OR has_schema_privilege('service_role','bl20_review_ledger_v1_private','USAGE')
 OR has_function_privilege('anon','bl20_review_ledger_v1_private.stage_review_evidence(uuid,text,text,text,text,text,text,text,timestamptz)','EXECUTE')
 OR has_function_privilege('authenticated','bl20_review_ledger_v1_private.stage_review_evidence(uuid,text,text,text,text,text,text,text,timestamptz)','EXECUTE')
 OR has_function_privilege('service_role','bl20_review_ledger_v1_private.stage_review_evidence(uuid,text,text,text,text,text,text,text,timestamptz)','EXECUTE')
 OR has_table_privilege('service_role','bl20_review_ledger_v1_private.receipts','INSERT')
 THEN RAISE EXCEPTION 'FAIL: review ledger publicly accessible'; END IF;

 -- One synthetic receipt is recorded atomically with one audit event.
 reply:=pg_temp.stage_evidence(a);
 IF reply->>'reviewEvidenceStagedOnly'<>'true'
 OR reply->>'deviceApproved'<>'false'
 OR reply->>'trustedDevice'<>'false'
 OR reply->>'e2eeReady'<>'false'
 OR reply->>'canActivate'<>'false'
 OR reply->>'enrollmentCommitted'<>'false'
 THEN RAISE EXCEPTION 'FAIL: review receipt misrepresented as approval'; END IF;

 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(a);
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: replay of existing intent'; END IF;

 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(b,repeat('7',64));
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: nonce replay across distinct intents'; END IF;

 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(b,repeat('8',64),repeat('2',64));
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: duplicate reviewer signing key digest'; END IF;

 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(b,repeat('8',64),repeat('1',64),
   pg_catalog.clock_timestamp()-interval '1 second');
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: expired receipt accepted'; END IF;

 UPDATE bl20_first_device_v1_private.review_intents
 SET state='governance_vetoed',vetoed_at=pg_catalog.clock_timestamp()
 WHERE id=b;
 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(b,repeat('8',64));
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: revoked governance intent staged'; END IF;
 UPDATE bl20_first_device_v1_private.review_intents
 SET state='governance_pending_review_only',vetoed_at=NULL WHERE id=b;

 UPDATE auth.sessions SET not_after=pg_catalog.clock_timestamp()-interval '1 second';
 blocked:=false;
 BEGIN PERFORM pg_temp.stage_evidence(b,repeat('8',64));
 EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: expired auth session accepted'; END IF;
 UPDATE auth.sessions SET not_after=pg_catalog.clock_timestamp()+interval '15 minutes';

 blocked:=false;
 BEGIN
  UPDATE bl20_review_ledger_v1_private.receipts
  SET state='review_evidence_staged_only' WHERE intent_id=a;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: receipt can be rewritten'; END IF;

 blocked:=false;
 BEGIN DELETE FROM bl20_review_ledger_v1_private.events WHERE intent_id=a;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL: audit event can be deleted'; END IF;

 IF (SELECT count(*) FROM bl20_review_ledger_v1_private.receipts)<>1
 OR (SELECT count(*) FROM bl20_review_ledger_v1_private.events)<>1
 OR (SELECT count(*) FROM public.messaging_devices)<>0
 THEN RAISE EXCEPTION 'FAIL: rejected request mutated trust or audit state'; END IF;
 RAISE NOTICE 'PASS: nonce/replay/veto/session/expiry/immutability/privilege checks';
END;
$test$;
