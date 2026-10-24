-- V39 disposable-only atomic recovery evidence ledger. NEVER apply to live DB.
-- A successful transaction records evidence consumption, NOT device authorization.
BEGIN;
CREATE SCHEMA bl_v39_atomic_recovery_lab;
CREATE TABLE bl_v39_atomic_recovery_lab.challenges (
 request_id uuid PRIMARY KEY, account_id uuid NOT NULL, candidate_device_id uuid NOT NULL,
 nonce_sha256 text NOT NULL CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 authorized boolean NOT NULL DEFAULT false CHECK (authorized = false)
);
CREATE TABLE bl_v39_atomic_recovery_lab.authority_receipts (
 receipt_id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES bl_v39_atomic_recovery_lab.challenges(request_id),
 account_id uuid NOT NULL, candidate_device_id uuid NOT NULL,
 issuer_id text NOT NULL, verified_by_server boolean NOT NULL DEFAULT false,
 revoked_at timestamptz, consumed_at timestamptz,
 UNIQUE (request_id), CHECK (verified_by_server = false OR issuer_id <> '')
);
CREATE TABLE bl_v39_atomic_recovery_lab.consumption_audit (
 request_id uuid PRIMARY KEY REFERENCES bl_v39_atomic_recovery_lab.challenges(request_id),
 receipt_id uuid NOT NULL UNIQUE REFERENCES bl_v39_atomic_recovery_lab.authority_receipts(receipt_id),
 account_id uuid NOT NULL, consumed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE bl_v39_atomic_recovery_lab.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_atomic_recovery_lab.challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_atomic_recovery_lab.authority_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_atomic_recovery_lab.authority_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_atomic_recovery_lab.consumption_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_atomic_recovery_lab.consumption_audit FORCE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA bl_v39_atomic_recovery_lab FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_v39_atomic_recovery_lab FROM PUBLIC;
INSERT INTO bl_v39_atomic_recovery_lab.challenges
 VALUES ('22222222-2222-4222-8222-222222222222',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333',repeat('a',64),
 now()+interval '5 minutes',NULL,false);
INSERT INTO bl_v39_atomic_recovery_lab.authority_receipts
 VALUES ('44444444-4444-4444-8444-444444444444',
 '22222222-2222-4222-8222-222222222222',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333','independent-verifier-lab',false,NULL,NULL);
-- A single conditional UPDATE with row locks and matching receipt/challenge identity.
-- Only a trusted service can set verified_by_server in a real system, after
-- independently validating cryptographic issuer, audience, expiry and nonce.
CREATE FUNCTION bl_v39_atomic_recovery_lab.consume_evidence(
 p_request uuid,p_receipt uuid,p_account uuid,p_device uuid,p_nonce text
) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE updated_receipt integer; updated_challenge integer;
BEGIN
 UPDATE bl_v39_atomic_recovery_lab.authority_receipts r
 SET consumed_at=now()
 FROM bl_v39_atomic_recovery_lab.challenges c
 WHERE r.receipt_id=p_receipt AND r.request_id=p_request
 AND r.account_id=p_account AND r.candidate_device_id=p_device
 AND r.verified_by_server=true AND r.revoked_at IS NULL
 AND r.consumed_at IS NULL
 AND c.request_id=r.request_id AND c.account_id=p_account
 AND c.candidate_device_id=p_device AND c.nonce_sha256=p_nonce
 AND c.consumed_at IS NULL AND c.expires_at>now() AND c.authorized=false;
 GET DIAGNOSTICS updated_receipt=ROW_COUNT;
 IF updated_receipt<>1 THEN RETURN false; END IF;
 UPDATE bl_v39_atomic_recovery_lab.challenges
 SET consumed_at=now()
 WHERE request_id=p_request AND account_id=p_account
 AND candidate_device_id=p_device AND nonce_sha256=p_nonce
 AND consumed_at IS NULL AND expires_at>now() AND authorized=false;
 GET DIAGNOSTICS updated_challenge=ROW_COUNT;
 IF updated_challenge<>1 THEN RAISE EXCEPTION 'CHALLENGE_CONSUMPTION_RACE'; END IF;
 INSERT INTO bl_v39_atomic_recovery_lab.consumption_audit(request_id,receipt_id,account_id)
 VALUES(p_request,p_receipt,p_account);
 RETURN true;
END $$;
-- The disposable vanilla PostgreSQL service does not provision Supabase roles.
-- Create NOLOGIN stand-ins inside this rolled-back transaction solely for ACL tests.
DO $roles$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
  CREATE ROLE anon NOLOGIN;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
  CREATE ROLE authenticated NOLOGIN;
 END IF;
END $roles$;
-- PostgreSQL grants EXECUTE on new functions to PUBLIC by default.
-- Explicitly revoke this privilege even in the disposable lab.
REVOKE ALL ON FUNCTION bl_v39_atomic_recovery_lab.consume_evidence(uuid,uuid,uuid,uuid,text) FROM PUBLIC;
DO $privilege_checks$
BEGIN
 IF has_schema_privilege('anon','bl_v39_atomic_recovery_lab','USAGE')
 OR has_schema_privilege('authenticated','bl_v39_atomic_recovery_lab','USAGE')
 THEN RAISE EXCEPTION 'client role can access private recovery schema'; END IF;
 IF has_function_privilege('anon',
   'bl_v39_atomic_recovery_lab.consume_evidence(uuid,uuid,uuid,uuid,text)','EXECUTE')
 OR has_function_privilege('authenticated',
   'bl_v39_atomic_recovery_lab.consume_evidence(uuid,uuid,uuid,uuid,text)','EXECUTE')
 THEN RAISE EXCEPTION 'client role can execute recovery consumption'; END IF;
END $privilege_checks$;
DO $checks$
DECLARE accepted boolean;
BEGIN
 SELECT bl_v39_atomic_recovery_lab.consume_evidence(
 '22222222-2222-4222-8222-222222222222',
 '44444444-4444-4444-8444-444444444444',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333',repeat('a',64)) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'unverified receipt accepted'; END IF;
 UPDATE bl_v39_atomic_recovery_lab.authority_receipts SET verified_by_server=true;
 SELECT bl_v39_atomic_recovery_lab.consume_evidence(
 '22222222-2222-4222-8222-222222222222',
 '44444444-4444-4444-8444-444444444444',
 '99999999-9999-4999-8999-999999999999',
 '33333333-3333-4333-8333-333333333333',repeat('a',64)) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'cross-account receipt accepted'; END IF;
 SELECT bl_v39_atomic_recovery_lab.consume_evidence(
 '22222222-2222-4222-8222-222222222222',
 '44444444-4444-4444-8444-444444444444',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333',repeat('b',64)) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'wrong nonce accepted'; END IF;
 SELECT bl_v39_atomic_recovery_lab.consume_evidence(
 '22222222-2222-4222-8222-222222222222',
 '44444444-4444-4444-8444-444444444444',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333',repeat('a',64)) INTO accepted;
 IF NOT accepted THEN RAISE EXCEPTION 'valid evidence not consumed'; END IF;
 SELECT bl_v39_atomic_recovery_lab.consume_evidence(
 '22222222-2222-4222-8222-222222222222',
 '44444444-4444-4444-8444-444444444444',
 '11111111-1111-4111-8111-111111111111',
 '33333333-3333-4333-8333-333333333333',repeat('a',64)) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'replay accepted'; END IF;
 IF (SELECT count(*) FROM bl_v39_atomic_recovery_lab.consumption_audit)<>1
 THEN RAISE EXCEPTION 'audit not unique'; END IF;
 IF (SELECT bool_or(authorized) FROM bl_v39_atomic_recovery_lab.challenges)
 THEN RAISE EXCEPTION 'evidence consumption authorized enrollment'; END IF;
END $checks$;
ROLLBACK;
