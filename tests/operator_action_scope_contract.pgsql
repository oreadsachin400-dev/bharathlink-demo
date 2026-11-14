\set ON_ERROR_STOP on
\echo 'OPERATOR ACTION SCOPES + AUTH SESSION SHAPE — disposable PG16'

-- Synthetic minimum of auth schema columns read-only inspected in official
-- BharathLink-20 TEST on 14 Nov; no auth.users or auth.sessions data copied.
CREATE TYPE auth.aal_level AS ENUM ('aal1','aal2');
CREATE TABLE auth.users(
 id uuid PRIMARY KEY,
 role text NOT NULL,
 is_anonymous boolean NOT NULL DEFAULT false,
 confirmed_at timestamptz,
 deleted_at timestamptz,
 banned_until timestamptz
);
CREATE TABLE auth.sessions(
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES auth.users(id),
 aal auth.aal_level,
 not_after timestamptz
);
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON auth.users,auth.sessions FROM PUBLIC,anon,authenticated,service_role;

INSERT INTO auth.users(id,role,is_anonymous,confirmed_at) VALUES(
 '44444444-4444-4444-8444-444444444444','authenticated',false,
 clock_timestamp()-interval '1 day'
);
INSERT INTO auth.sessions(id,user_id,aal,not_after) VALUES(
 '77777777-7777-4777-8777-777777777777',
 '44444444-4444-4444-8444-444444444444',
 'aal2',clock_timestamp()+interval '7 days'
);

DO $empty$
BEGIN
 IF EXISTS(SELECT 1 FROM bl_directory_lab.operator_action_scopes)
 THEN RAISE EXCEPTION 'Registry began with unauthorized scope'; END IF;
END $empty$;
\echo 'PASS: Operator action registry starts empty, with no automatic Verified capability.'

INSERT INTO bl_directory_lab.operator_action_scopes(
 user_id,action,granted_by,active
) VALUES
('44444444-4444-4444-8444-444444444444','issue',
 '22222222-2222-4222-8222-222222222222',true),
('33333333-3333-4333-8333-333333333333','revoke',
 '22222222-2222-4222-8222-222222222222',true);
DO $check$
BEGIN
 IF (SELECT count(*) FROM bl_directory_lab.operator_scope_events
     WHERE event='scope_granted')<>2
 OR (SELECT count(*) FROM bl_directory_lab.operator_action_scopes
     WHERE active)<>2 THEN
 RAISE EXCEPTION 'Independent scope grants were not audited'; END IF;
END $check$;
\echo 'PASS: Issuer and independent revoker scopes are explicitly provisioned and append-only audited.'

-- Third actor is invented to prove terminal revocation rules, leaving
-- the issuer/revoker roles available for subsequent query-adapter tests.
INSERT INTO bl_directory_lab.publisher_operators(
 user_id,provisioned_by,active
) VALUES(
 '55555555-5555-4555-8555-555555555555',
 '22222222-2222-4222-8222-222222222222',true
);
INSERT INTO bl_directory_lab.operator_action_scopes(
 user_id,action,granted_by
) VALUES(
 '55555555-5555-4555-8555-555555555555',
 'issue','22222222-2222-4222-8222-222222222222'
);

DO $self_grant$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  INSERT INTO bl_directory_lab.operator_action_scopes(
    user_id,action,granted_by
  ) VALUES(
    '55555555-5555-4555-8555-555555555555','revoke',
    '55555555-5555-4555-8555-555555555555'
  );
 EXCEPTION WHEN check_violation THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'Self-authorized operator gained revoke scope'; END IF;
END $self_grant$;
\echo 'PASS: Operator cannot grant their own trusted scope.'

UPDATE bl_directory_lab.operator_action_scopes
SET active=false,revoked_at=clock_timestamp(),
 revoked_by='99999999-9999-4999-8999-999999999999'
WHERE user_id='55555555-5555-4555-8555-555555555555'
  AND action='issue';
DO $check$
BEGIN
 IF (SELECT active FROM bl_directory_lab.operator_action_scopes
  WHERE user_id='55555555-5555-4555-8555-555555555555'
    AND action='issue')
 OR (SELECT count(*) FROM bl_directory_lab.operator_scope_events
  WHERE user_id='55555555-5555-4555-8555-555555555555')<>2
 THEN RAISE EXCEPTION 'Scope revocation state/audit incorrect'; END IF;
END $check$;
\echo 'PASS: Separate revoker disables operator scope with immutable revocation record.'

DO $revert_denied$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  UPDATE bl_directory_lab.operator_action_scopes
  SET active=true,revoked_at=NULL,revoked_by=NULL
  WHERE user_id='55555555-5555-4555-8555-555555555555'
    AND action='issue';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'Terminal revoked scope reactivated'; END IF;
 blocked:=false;
 BEGIN
  DELETE FROM bl_directory_lab.operator_action_scopes
  WHERE user_id='55555555-5555-4555-8555-555555555555';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'Operator scope deleted'; END IF;
END $revert_denied$;
\echo 'PASS: Terminally revoked operator scope cannot be reactivated or deleted.'

DO $audit_immutable$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  DELETE FROM bl_directory_lab.operator_scope_events
  WHERE user_id='55555555-5555-4555-8555-555555555555';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'Operator scope audit deletable'; END IF;
END $audit_immutable$;
\echo 'PASS: Grant/revoke operator event ledger is append-only.'

DO $acl$
BEGIN
 IF has_table_privilege('anon','bl_directory_lab.operator_action_scopes','SELECT')
 OR has_table_privilege('authenticated','bl_directory_lab.operator_action_scopes','SELECT')
 OR has_table_privilege('service_role','bl_directory_lab.operator_action_scopes','SELECT')
 OR has_table_privilege('authenticated','auth.sessions','SELECT')
 THEN RAISE EXCEPTION 'App role has private operator or session information'; END IF;
END $acl$;
\echo 'PASS: App roles have no private operator-scope or auth.sessions table grant.'
