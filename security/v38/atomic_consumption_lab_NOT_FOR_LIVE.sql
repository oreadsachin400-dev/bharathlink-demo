-- ISOLATED PostgreSQL SECURITY TEST ONLY. Do not deploy.
-- Demonstrates atomic one-time consumption after a verifier has authenticated
-- a request; it DOES NOT verify signatures or authorize a real device.
BEGIN;
CREATE SCHEMA bl_v38_atomic_lab;
CREATE TABLE bl_v38_atomic_lab.requests(
 request_id uuid PRIMARY KEY,
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL,
 candidate_key_sha256 text NOT NULL CHECK(candidate_key_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','consumed','cancelled'))
);
CREATE TABLE bl_v38_atomic_lab.v2_devices(
 device_id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 signing_public_key text NOT NULL,
 curve25519_public_key text NOT NULL,
 protocol_version integer NOT NULL DEFAULT 2 CHECK(protocol_version=2),
 UNIQUE(user_id,device_id)
);
CREATE TABLE bl_v38_atomic_lab.consumptions(
 request_id uuid PRIMARY KEY REFERENCES bl_v38_atomic_lab.requests(request_id),
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL,
 candidate_key_sha256 text NOT NULL,
 consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_id,candidate_device_id)
);
CREATE FUNCTION bl_v38_atomic_lab.consume_verified_request(
 p_request_id uuid,p_account_id uuid,p_candidate_device_id uuid,p_candidate_key_sha256 text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE v_count integer;
BEGIN
 -- A caller cannot use this reference function as proof of signature verification.
 -- Access is revoked and no grant is made.
 UPDATE bl_v38_atomic_lab.requests
 SET state='consumed'
 WHERE request_id=p_request_id AND account_id=p_account_id
   AND candidate_device_id=p_candidate_device_id
   AND candidate_key_sha256=p_candidate_key_sha256
   AND state='pending' AND expires_at>clock_timestamp();
 GET DIAGNOSTICS v_count=ROW_COUNT;
 IF v_count<>1 THEN RETURN false; END IF;
 INSERT INTO bl_v38_atomic_lab.consumptions(request_id,account_id,candidate_device_id,candidate_key_sha256)
 VALUES(p_request_id,p_account_id,p_candidate_device_id,p_candidate_key_sha256);
 RETURN true;
END $$;
REVOKE ALL ON SCHEMA bl_v38_atomic_lab FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_v38_atomic_lab FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bl_v38_atomic_lab FROM PUBLIC;
DO $$
DECLARE a uuid:='11111111-1111-4111-8111-111111111111';
        d uuid:='33333333-3333-4333-8333-333333333333';
        r uuid:='22222222-2222-4222-8222-222222222223';
        k text:=repeat('a',64);
BEGIN
 INSERT INTO bl_v38_atomic_lab.requests VALUES(r,a,d,k,clock_timestamp()+interval '2 minutes','pending');
 IF bl_v38_atomic_lab.consume_verified_request(r,a,d,repeat('b',64)) THEN RAISE EXCEPTION 'candidate key substitution accepted'; END IF;
 IF bl_v38_atomic_lab.consume_verified_request(r,'99999999-9999-4999-8999-999999999999',d,k) THEN RAISE EXCEPTION 'cross-account consume accepted'; END IF;
 IF bl_v38_atomic_lab.consume_verified_request(r,a,'88888888-8888-4888-8888-888888888888',k) THEN RAISE EXCEPTION 'device substitution accepted'; END IF;
 IF (SELECT state FROM bl_v38_atomic_lab.requests WHERE request_id=r)<>'pending' THEN RAISE EXCEPTION 'rejected approval mutated request'; END IF;
 IF NOT bl_v38_atomic_lab.consume_verified_request(r,a,d,k) THEN RAISE EXCEPTION 'first consume failed'; END IF;
 IF bl_v38_atomic_lab.consume_verified_request(r,a,d,k) THEN RAISE EXCEPTION 'replay accepted'; END IF;
 IF (SELECT count(*) FROM bl_v38_atomic_lab.consumptions)<>1 THEN RAISE EXCEPTION 'duplicate receipt'; END IF;
 -- Actual PostgreSQL savepoint/exception rollback, not a simulated JS rollback.
 BEGIN
  INSERT INTO bl_v38_atomic_lab.v2_devices(device_id,user_id,signing_public_key,curve25519_public_key)
  VALUES('55555555-5555-4555-8555-555555555555',a,'signing','curve');
  RAISE EXCEPTION 'injected failure after device insert';
 EXCEPTION WHEN raise_exception THEN NULL;
 END;
 IF EXISTS(SELECT 1 FROM bl_v38_atomic_lab.v2_devices WHERE device_id='55555555-5555-4555-8555-555555555555')
 THEN RAISE EXCEPTION 'failed transaction retained inserted device'; END IF;

 INSERT INTO bl_v38_atomic_lab.requests VALUES('22222222-2222-4222-8222-222222222224',a,d,k,clock_timestamp()-interval '1 second','pending');
 IF bl_v38_atomic_lab.consume_verified_request('22222222-2222-4222-8222-222222222224',a,d,k) THEN RAISE EXCEPTION 'expired accepted'; END IF;
 INSERT INTO bl_v38_atomic_lab.requests VALUES('22222222-2222-4222-8222-222222222225',a,'44444444-4444-4444-8444-444444444444',k,clock_timestamp()+interval '2 minutes','cancelled');
 IF bl_v38_atomic_lab.consume_verified_request('22222222-2222-4222-8222-222222222225',a,'44444444-4444-4444-8444-444444444444',k) THEN RAISE EXCEPTION 'cancelled accepted'; END IF;
END $$;
ROLLBACK;
