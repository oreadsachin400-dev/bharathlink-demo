-- Disposable PostgreSQL transaction exercise ONLY; NOT cryptographic verification.
-- Authorization must happen inside a trusted server boundary, with locks.
BEGIN;
CREATE SCHEMA bl_v39_atomic_lab;
CREATE TABLE bl_v39_atomic_lab.requests (
 id integer PRIMARY KEY, account_id integer NOT NULL,
 candidate_device_id integer NOT NULL, state text NOT NULL
 CHECK (state IN ('pending','consumed'))
);
CREATE TABLE bl_v39_atomic_lab.devices (
 account_id integer NOT NULL, device_id integer NOT NULL,
 request_id integer NOT NULL UNIQUE,
 PRIMARY KEY (account_id,device_id)
);
CREATE TABLE bl_v39_atomic_lab.receipts (
 request_id integer PRIMARY KEY, account_id integer NOT NULL,
 candidate_device_id integer NOT NULL
);
INSERT INTO bl_v39_atomic_lab.requests VALUES (1,11,22,'pending'),(2,11,23,'pending');
-- In a real service, trusted verification MUST precede the atomic finalizer
-- while the request and trusted anchor remain locked in the same transaction.
CREATE FUNCTION bl_v39_atomic_lab.consume_locked(
 p_id integer,p_account integer,p_candidate integer)
RETURNS boolean LANGUAGE plpgsql SET search_path='' AS $fn$
DECLARE changed integer;
BEGIN
 UPDATE bl_v39_atomic_lab.requests SET state='consumed'
 WHERE id=p_id AND account_id=p_account AND candidate_device_id=p_candidate
 AND state='pending';
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RETURN false; END IF;
 INSERT INTO bl_v39_atomic_lab.devices(account_id,device_id,request_id)
 VALUES(p_account,p_candidate,p_id);
 INSERT INTO bl_v39_atomic_lab.receipts(request_id,account_id,candidate_device_id)
 VALUES(p_id,p_account,p_candidate);
 RETURN true;
END $fn$;
DO $test$
BEGIN
 IF bl_v39_atomic_lab.consume_locked(1,99,22) THEN
  RAISE EXCEPTION 'cross-account request accepted'; END IF;
 IF bl_v39_atomic_lab.consume_locked(1,11,99) THEN
  RAISE EXCEPTION 'wrong candidate accepted'; END IF;
 IF NOT bl_v39_atomic_lab.consume_locked(1,11,22) THEN
  RAISE EXCEPTION 'valid pending request rejected'; END IF;
 IF bl_v39_atomic_lab.consume_locked(1,11,22) THEN
  RAISE EXCEPTION 'replay accepted'; END IF;
 BEGIN
  PERFORM bl_v39_atomic_lab.consume_locked(2,11,22);
  RAISE EXCEPTION 'duplicate candidate accepted';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 IF (SELECT state FROM bl_v39_atomic_lab.requests WHERE id=2)<>'pending'
 THEN RAISE EXCEPTION 'duplicate failure did not rollback statement'; END IF;
 IF (SELECT count(*) FROM bl_v39_atomic_lab.devices)<>1 OR
    (SELECT count(*) FROM bl_v39_atomic_lab.receipts)<>1
 THEN RAISE EXCEPTION 'atomic enrollment counts incorrect'; END IF;
END $test$;
ROLLBACK;
