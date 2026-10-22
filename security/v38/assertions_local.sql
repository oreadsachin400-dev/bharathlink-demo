\set ON_ERROR_STOP on
-- Tests execute as local database owner, and explicit role grants are checked separately.
DO $$ BEGIN
 IF to_regclass('bl_trust_v8_private.anchors') IS NULL OR
    to_regclass('bl_trust_v8_private.requests') IS NULL THEN
  RAISE EXCEPTION 'required tables missing';
 END IF;
END $$;
DO $$
DECLARE err text; rejected boolean := false;
BEGIN
 BEGIN
  INSERT INTO bl_trust_v8_private.requests
   (request_id,account_id,candidate_device_id,approver_device_id,candidate_signing_key,nonce,transcript_sha256,expires_at)
  VALUES ('22222222-2222-4222-8222-222222222222',
   '11111111-1111-4111-8111-111111111111',
   '33333333-3333-4333-8333-333333333333',
   '44444444-4444-4444-8444-444444444444',
   'dummy','nonce-1234567890123456789012',repeat('a',64),clock_timestamp()-interval '1 minute');
 EXCEPTION WHEN raise_exception THEN
  GET STACKED DIAGNOSTICS err = MESSAGE_TEXT;
  IF err <> 'invalid request expiry' THEN RAISE EXCEPTION 'wrong expiry failure: %',err; END IF;
  rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'expired request accepted'; END IF;
END $$;
INSERT INTO bl_trust_v8_private.requests
(request_id,account_id,candidate_device_id,approver_device_id,candidate_signing_key,nonce,transcript_sha256,expires_at)
VALUES ('22222222-2222-4222-8222-222222222223',
'11111111-1111-4111-8111-111111111111',
'33333333-3333-4333-8333-333333333333',
'44444444-4444-4444-8444-444444444444',
'dummy','nonce-1234567890123456789013',repeat('a',64),clock_timestamp()+interval '2 minutes');
-- A request 11 minutes in future must be rejected by the exact expiry trigger.
DO $$
DECLARE err text; rejected boolean := false;
BEGIN
 BEGIN
  INSERT INTO bl_trust_v8_private.requests
  (request_id,account_id,candidate_device_id,approver_device_id,candidate_signing_key,nonce,transcript_sha256,expires_at)
  VALUES ('22222222-2222-4222-8222-222222222224',
  '11111111-1111-4111-8111-111111111111',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444',
  'dummy','nonce-1234567890123456789014',repeat('a',64),clock_timestamp()+interval '11 minutes');
 EXCEPTION WHEN raise_exception THEN
  GET STACKED DIAGNOSTICS err = MESSAGE_TEXT;
  IF err <> 'invalid request expiry' THEN RAISE EXCEPTION 'wrong future expiry failure: %',err; END IF;
  rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'overlong request accepted'; END IF;
END $$;
-- Verify exact fail-closed finalizer exception.
DO $$
DECLARE err text; rejected boolean := false;
BEGIN
 BEGIN
  PERFORM bl_trust_v8_private.finalize_verified_approval(
   '22222222-2222-4222-8222-222222222223',
   '11111111-1111-4111-8111-111111111111',repeat('a',64),repeat('b',64),repeat('c',64));
 EXCEPTION WHEN insufficient_privilege THEN
  GET STACKED DIAGNOSTICS err = MESSAGE_TEXT;
  IF err <> 'device approval disabled until trusted verifier integration' THEN
   RAISE EXCEPTION 'wrong finalizer failure: %',err;
  END IF;
  rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'finalizer unexpectedly succeeded'; END IF;
END $$;
DO $$
DECLARE role_name text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF has_schema_privilege(role_name,'bl_trust_v8_private','CREATE') THEN
   RAISE EXCEPTION 'role % has CREATE on private schema',role_name;
  END IF;
  IF role_name IN ('anon','authenticated') AND has_schema_privilege(role_name,'bl_trust_v8_private','USAGE') THEN
   RAISE EXCEPTION 'role % has USAGE on private schema',role_name;
  END IF;
  IF role_name = 'service_role' AND NOT has_schema_privilege(role_name,'bl_trust_v8_private','USAGE') THEN
   RAISE EXCEPTION 'service_role missing expected schema USAGE';
  END IF;
  IF EXISTS (
   SELECT 1 FROM (VALUES ('anchors'),('requests'),('receipts'),('approved_devices')) AS t(tab)
   WHERE has_table_privilege(role_name,format('bl_trust_v8_private.%I',t.tab), 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  ) THEN
   RAISE EXCEPTION 'role % has direct private table privileges',role_name;
  END IF;
  IF has_table_privilege(role_name,'bl_trust_v8_private.requests','INSERT') THEN
   RAISE EXCEPTION 'role % has INSERT on private requests',role_name;
  END IF;
  IF has_function_privilege(role_name,
   'bl_trust_v8_private.finalize_verified_approval(uuid,uuid,text,text,text)','EXECUTE') THEN
   RAISE EXCEPTION 'role % can invoke disabled finalizer',role_name;
  END IF;
 END LOOP;
END $$;
SELECT 'ALL V31 LOCAL POSTGRES ASSERTIONS PASSED' AS result;
