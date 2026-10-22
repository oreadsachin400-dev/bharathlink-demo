-- V39 design experiment: disposable PostgreSQL ONLY. NOT A LIVE MIGRATION.
-- Existing bl_pairing_private.requests is insufficient for V2 key binding.
-- All keys are immutable after insertion. Application MUST verify actual key
-- encodings and recompute canonical digest; SQL below is a storage boundary,
-- NOT cryptographic authorization or first-device bootstrap.
BEGIN;
CREATE SCHEMA bl_v39_candidate_lab;
REVOKE ALL ON SCHEMA bl_v39_candidate_lab FROM PUBLIC;
CREATE TABLE bl_v39_candidate_lab.requests (
 request_id uuid PRIMARY KEY,
 account_id uuid NOT NULL REFERENCES auth.users(id),
 candidate_device_id uuid NOT NULL,
 approver_device_id uuid NOT NULL,
 candidate_signing_public_key text NOT NULL,
 candidate_curve25519_public_key text NOT NULL,
 candidate_key_sha256 text NOT NULL CHECK(candidate_key_sha256 ~ '^[0-9a-f]{64}$'),
 nonce_sha256 text NOT NULL CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','cancelled','expired')),
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(candidate_device_id <> approver_device_id),
 CHECK(length(candidate_signing_public_key) BETWEEN 40 AND 180),
 CHECK(length(candidate_curve25519_public_key) BETWEEN 40 AND 100),
 UNIQUE(account_id,candidate_device_id)
);
CREATE FUNCTION bl_v39_candidate_lab.immutable_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path='' AS $$
BEGIN
 IF (OLD.request_id,OLD.account_id,OLD.candidate_device_id,OLD.approver_device_id,
     OLD.candidate_signing_public_key,OLD.candidate_curve25519_public_key,
     OLD.candidate_key_sha256,OLD.nonce_sha256,OLD.expires_at)
 IS DISTINCT FROM
    (NEW.request_id,NEW.account_id,NEW.candidate_device_id,NEW.approver_device_id,
     NEW.candidate_signing_public_key,NEW.candidate_curve25519_public_key,
     NEW.candidate_key_sha256,NEW.nonce_sha256,NEW.expires_at)
 THEN RAISE EXCEPTION 'immutable enrollment binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_binding BEFORE UPDATE ON bl_v39_candidate_lab.requests
FOR EACH ROW EXECUTE FUNCTION bl_v39_candidate_lab.immutable_binding();
ALTER TABLE bl_v39_candidate_lab.requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_v39_candidate_lab FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl_v39_candidate_lab.immutable_binding() FROM PUBLIC,anon,authenticated,service_role;
DO $$
DECLARE a uuid := '11111111-1111-4111-8111-111111111111';
BEGIN
 INSERT INTO bl_v39_candidate_lab.requests(request_id,account_id,candidate_device_id,approver_device_id,candidate_signing_public_key,candidate_curve25519_public_key,candidate_key_sha256,nonce_sha256,expires_at)
 VALUES('22222222-2222-4222-8222-222222222222',a,'33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444',repeat('A',44),repeat('B',44),repeat('a',64),repeat('b',64),now()+interval '5 minutes');
 BEGIN
  UPDATE bl_v39_candidate_lab.requests SET candidate_key_sha256=repeat('c',64);
  RAISE EXCEPTION 'test failed: binding was mutable';
 EXCEPTION WHEN check_violation THEN NULL; END;
 IF (SELECT candidate_key_sha256 FROM bl_v39_candidate_lab.requests LIMIT 1) <> repeat('a',64)
 THEN RAISE EXCEPTION 'test failed: original digest changed'; END IF;
 IF has_schema_privilege('authenticated','bl_v39_candidate_lab','USAGE')
 THEN RAISE EXCEPTION 'test failed: exposed private schema'; END IF;
END $$;
ROLLBACK;
