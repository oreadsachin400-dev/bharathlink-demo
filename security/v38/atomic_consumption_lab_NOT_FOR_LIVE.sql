-- ISOLATED PostgreSQL SECURITY TEST ONLY. Do not deploy.
-- Demonstrates atomic one-time consumption after a verifier has authenticated
-- a request; it DOES NOT verify signatures or authorize a real device.
BEGIN;
CREATE SCHEMA bl_v38_atomic_lab;
CREATE TABLE bl_v38_atomic_lab.requests(
 request_id uuid PRIMARY KEY,
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL,
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','consumed','cancelled'))
);
CREATE TABLE bl_v38_atomic_lab.consumptions(
 request_id uuid PRIMARY KEY REFERENCES bl_v38_atomic_lab.requests(request_id),
 account_id uuid NOT NULL,
 candidate_device_id uuid NOT NULL,
 consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_id,candidate_device_id)
);
CREATE FUNCTION bl_v38_atomic_lab.consume_verified_request(
 p_request_id uuid,p_account_id uuid,p_candidate_device_id uuid
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE v_count integer;
BEGIN
 -- A caller cannot use this reference function as proof of signature verification.
 -- Access is revoked and no grant is made.
 UPDATE bl_v38_atomic_lab.requests
 SET state='consumed'
 WHERE request_id=p_request_id AND account_id=p_account_id
   AND candidate_device_id=p_candidate_device_id
   AND state='pending' AND expires_at>clock_timestamp();
 GET DIAGNOSTICS v_count=ROW_COUNT;
 IF v_count<>1 THEN RETURN false; END IF;
 INSERT INTO bl_v38_atomic_lab.consumptions(request_id,account_id,candidate_device_id)
 VALUES(p_request_id,p_account_id,p_candidate_device_id);
 RETURN true;
END $$;
REVOKE ALL ON SCHEMA bl_v38_atomic_lab FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA bl_v38_atomic_lab FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bl_v38_atomic_lab FROM PUBLIC;
DO $$
DECLARE a uuid:='11111111-1111-4111-8111-111111111111';
        d uuid:='33333333-3333-4333-8333-333333333333';
        r uuid:='22222222-2222-4222-8222-222222222223';
BEGIN
 INSERT INTO bl_v38_atomic_lab.requests VALUES(r,a,d,clock_timestamp()+interval '2 minutes','pending');
 IF NOT bl_v38_atomic_lab.consume_verified_request(r,a,d) THEN RAISE EXCEPTION 'first consume failed'; END IF;
 IF bl_v38_atomic_lab.consume_verified_request(r,a,d) THEN RAISE EXCEPTION 'replay accepted'; END IF;
 IF (SELECT count(*) FROM bl_v38_atomic_lab.consumptions)<>1 THEN RAISE EXCEPTION 'duplicate receipt'; END IF;
 INSERT INTO bl_v38_atomic_lab.requests VALUES('22222222-2222-4222-8222-222222222224',a,d,clock_timestamp()-interval '1 second','pending');
 IF bl_v38_atomic_lab.consume_verified_request('22222222-2222-4222-8222-222222222224',a,d) THEN RAISE EXCEPTION 'expired accepted'; END IF;
 INSERT INTO bl_v38_atomic_lab.requests VALUES('22222222-2222-4222-8222-222222222225',a,'44444444-4444-4444-8444-444444444444',clock_timestamp()+interval '2 minutes','cancelled');
 IF bl_v38_atomic_lab.consume_verified_request('22222222-2222-4222-8222-222222222225',a,'44444444-4444-4444-8444-444444444444') THEN RAISE EXCEPTION 'cancelled accepted'; END IF;
END $$;
ROLLBACK;
