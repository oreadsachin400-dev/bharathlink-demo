-- Disposable PostgreSQL recovery challenge replay/privilege lab. NOT FOR LIVE.
-- This tests one-time challenge consumption ONLY; never authorizes device enrollment.
BEGIN;
CREATE SCHEMA bl_v39_recovery_lab;
CREATE TABLE bl_v39_recovery_lab.challenges (
 request_id uuid PRIMARY KEY, account_id uuid NOT NULL, candidate_device_id uuid NOT NULL,
 nonce_sha256 text NOT NULL CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 authorized boolean NOT NULL DEFAULT false
);
ALTER TABLE bl_v39_recovery_lab.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_v39_recovery_lab.challenges FORCE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA bl_v39_recovery_lab FROM PUBLIC;
REVOKE ALL ON bl_v39_recovery_lab.challenges FROM PUBLIC;
INSERT INTO bl_v39_recovery_lab.challenges(request_id,account_id,candidate_device_id,nonce_sha256,expires_at)
VALUES('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',
'33333333-3333-4333-8333-333333333333',repeat('a',64),now()+interval '5 minutes');
DO $checks$
DECLARE n integer;
BEGIN
 UPDATE bl_v39_recovery_lab.challenges SET consumed_at=now()
 WHERE request_id='22222222-2222-4222-8222-222222222222'
 AND account_id='99999999-9999-4999-8999-999999999999'
 AND consumed_at IS NULL AND expires_at>now();
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>0 THEN RAISE EXCEPTION 'cross-account consumed challenge'; END IF;
 UPDATE bl_v39_recovery_lab.challenges SET consumed_at=now()
 WHERE request_id='22222222-2222-4222-8222-222222222222'
 AND account_id='11111111-1111-4111-8111-111111111111'
 AND candidate_device_id='33333333-3333-4333-8333-333333333333'
 AND nonce_sha256=repeat('a',64) AND consumed_at IS NULL
 AND expires_at>now() AND authorized=false;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'first challenge consumption failed'; END IF;
 UPDATE bl_v39_recovery_lab.challenges SET consumed_at=now()
 WHERE request_id='22222222-2222-4222-8222-222222222222'
 AND account_id='11111111-1111-4111-8111-111111111111'
 AND consumed_at IS NULL AND expires_at>now();
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>0 THEN RAISE EXCEPTION 'replay succeeded'; END IF;
 IF (SELECT authorized FROM bl_v39_recovery_lab.challenges LIMIT 1)<>false
 THEN RAISE EXCEPTION 'challenge consumption granted authority'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
 WHERE ns.nspname='bl_v39_recovery_lab' AND c.relname='challenges'
 AND c.relrowsecurity AND c.relforcerowsecurity)
 THEN RAISE EXCEPTION 'RLS not enforced'; END IF;
END $checks$;
ROLLBACK;
