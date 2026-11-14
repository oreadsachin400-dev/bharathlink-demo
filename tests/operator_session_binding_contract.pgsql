\set ON_ERROR_STOP on
\echo 'OPERATOR DB LOGIN BINDING — isolated PG16, no real users'

-- SQL logins are CI-only, unprivileged, and NOT Supabase Auth users.
-- A superuser simulates separate authenticated sessions by temporarily
-- setting SESSION AUTHORIZATION; normal roles cannot impersonate peers.
CREATE ROLE bl_lab_issuer LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE bl_lab_revoker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE bl_lab_outsider LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
INSERT INTO bl_directory_lab.db_operator_bindings(
  login_role,actor_user_id,permission,active,provisioned_by
) VALUES
 ('bl_lab_issuer','44444444-4444-4444-8444-444444444444',
  'issue',false,'22222222-2222-4222-8222-222222222222'),
 ('bl_lab_revoker','33333333-3333-4333-8333-333333333333',
  'revoke',false,'22222222-2222-4222-8222-222222222222');

-- The CI's "deployment" grants ONLY the two disposable login roles.
GRANT USAGE ON SCHEMA bl_directory_lab TO bl_lab_issuer,bl_lab_revoker;
GRANT EXECUTE ON FUNCTION
 bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)
 TO bl_lab_issuer;
GRANT EXECUTE ON FUNCTION
 bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)
 TO bl_lab_revoker;

DO $acl$
BEGIN
 IF has_function_privilege('anon',
  'bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)','EXECUTE')
 OR has_function_privilege('authenticated',
  'bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)','EXECUTE')
 OR has_function_privilege('service_role',
  'bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)','EXECUTE')
 OR has_function_privilege('anon',
  'bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)','EXECUTE')
 OR has_function_privilege('authenticated',
  'bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)','EXECUTE')
 OR has_function_privilege('service_role',
  'bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)','EXECUTE')
 OR has_function_privilege('bl_lab_issuer',
  'bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)','EXECUTE')
 OR has_function_privilege('bl_lab_revoker',
  'bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)','EXECUTE')
 OR has_function_privilege('bl_lab_issuer',
  'bl_directory_lab.issue_verified_entity_lab_v1(uuid,uuid,timestamptz)','EXECUTE')
 OR has_table_privilege('bl_lab_issuer',
  'bl_directory_lab.db_operator_bindings','SELECT')
 THEN RAISE EXCEPTION 'Insecure operator wrapper permissions'; END IF;
END $acl$;
\echo 'PASS: DB issuer/revoker get only scoped private wrapper grants, no raw client or private table grants.'

-- Valid independent evidence for a completely new synthetic organization.
-- Hashes are placeholders; no external authority is consulted.
INSERT INTO public.entity_profiles(
 id,entity_type,legal_name,verification_status,created_by,country_code
) VALUES(
 '10000000-0000-4000-8000-000000000030','business',
 'Synthetic Operator Session Binding Ltd','pending',
 '11111111-1111-4111-8111-111111111111','IN'
);
INSERT INTO public.entity_verification_requests(
 id,entity_id,requester_user_id,evidence_type,status
) VALUES(
 '40000000-0000-4000-8000-000000000030',
 '10000000-0000-4000-8000-000000000030',
 '11111111-1111-4111-8111-111111111111','gstin','pending'
);
INSERT INTO bl_directory_lab.review_decisions(
 request_id,reviewer_user_id,decision,evidence_sha256
) VALUES
 ('40000000-0000-4000-8000-000000000030',
  '88888888-8888-4888-8888-888888888888','approve',repeat('f',64)),
 ('40000000-0000-4000-8000-000000000030',
  '99999999-9999-4999-8999-999999999999','approve',repeat('f',64));
INSERT INTO bl_directory_lab.authority_attestations(
 request_id,attested_by,evidence_sha256,source_kind,
 source_reference_sha256,expires_at
) VALUES(
 '40000000-0000-4000-8000-000000000030',
 '22222222-2222-4222-8222-222222222222',
 repeat('f',64),'government_registry',repeat('e',64),
 clock_timestamp()+interval '60 days'
);
INSERT INTO bl_directory_lab.prepared_publications(
 request_id,entity_id,evidence_sha256,prepared_by
) VALUES(
 '40000000-0000-4000-8000-000000000030',
 '10000000-0000-4000-8000-000000000030',
 repeat('f',64),'66666666-6666-4666-8666-666666666666'
);

-- A role with no binding, even a synthetic JWT containing an issuer UUID,
-- cannot issue a badge or inspect the private session mapping.
SET SESSION AUTHORIZATION bl_lab_outsider;
DO $outsider$
DECLARE denied boolean:=false;
BEGIN
 PERFORM pg_catalog.set_config('request.jwt.claim.sub',
  '44444444-4444-4444-8444-444444444444',true);
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_bound_lab_v2(
   '40000000-0000-4000-8000-000000000030',
   pg_catalog.clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Outsider issued badge with spoofed JWT'; END IF;
END $outsider$;
RESET SESSION AUTHORIZATION;
\echo 'PASS: Unbound login cannot issue even when claiming a privileged JWT identity.'

SET SESSION AUTHORIZATION bl_lab_issuer;
DO $disabled$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_bound_lab_v2(
   '40000000-0000-4000-8000-000000000030',
   pg_catalog.clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Disabled bound issuer was accepted'; END IF;
END $disabled$;
RESET SESSION AUTHORIZATION;
\echo 'PASS: Database login with disabled operator binding cannot issue.'

UPDATE bl_directory_lab.db_operator_bindings
 SET active=true WHERE login_role='bl_lab_issuer';

SET SESSION AUTHORIZATION bl_lab_issuer;
DO $issue$
DECLARE got text;
BEGIN
 IF session_user<>'bl_lab_issuer' OR current_user<>'bl_lab_issuer'
 THEN RAISE EXCEPTION 'CI operator session identity not isolated'; END IF;
 -- Deliberately lie about Auth uid and role. Trusted actor is STILL derived
 -- solely from session_user and the private mapping.
 PERFORM pg_catalog.set_config('request.jwt.claim.sub',
  '33333333-3333-4333-8333-333333333333',true);
 PERFORM pg_catalog.set_config('request.jwt.claim.role',
  'service_role',true);
 got:=bl_directory_lab.issue_verified_entity_bound_lab_v2(
  '40000000-0000-4000-8000-000000000030',
  pg_catalog.clock_timestamp()+interval '30 days');
 IF got<>'entity_verified_endpoint_status_unchanged'
 THEN RAISE EXCEPTION 'Bound issuer got unexpected result'; END IF;
END $issue$;
RESET SESSION AUTHORIZATION;
DO $audit$
BEGIN
 IF (SELECT issued_by FROM bl_directory_lab.issued_badges
     WHERE entity_id='10000000-0000-4000-8000-000000000030')
       IS DISTINCT FROM '44444444-4444-4444-8444-444444444444'::uuid
 OR (SELECT verification_status FROM public.entity_profiles
     WHERE id='10000000-0000-4000-8000-000000000030') <> 'verified'
 THEN RAISE EXCEPTION 'Session login was not bound to recorded issuer'; END IF;
END $audit$;
\echo 'PASS: Valid operator login issues under mapped identity, ignores forged sub/role JWT claims.'

SET SESSION AUTHORIZATION bl_lab_issuer;
DO $no_revoke$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.revoke_verified_entity_bound_lab_v2(
   '10000000-0000-4000-8000-000000000030',
   'Spurious attempt to revoke own issued identity');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Issuer used revoker-only path'; END IF;
END $no_revoke$;
RESET SESSION AUTHORIZATION;
\echo 'PASS: Issuer cannot access independent revoker-only function.'

SET SESSION AUTHORIZATION bl_lab_revoker;
DO $disabled$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.revoke_verified_entity_bound_lab_v2(
   '10000000-0000-4000-8000-000000000030',
   'Independent operator revokes official identity');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Disabled bound revoker was accepted'; END IF;
END $disabled$;
RESET SESSION AUTHORIZATION;
\echo 'PASS: Disabled independent revoker cannot invalidate a Verified badge.'

UPDATE bl_directory_lab.db_operator_bindings
 SET active=true WHERE login_role='bl_lab_revoker';
SET SESSION AUTHORIZATION bl_lab_revoker;
DO $revoke$
DECLARE got text;
BEGIN
 PERFORM pg_catalog.set_config('request.jwt.claim.sub',
  '44444444-4444-4444-8444-444444444444',true);
 got:=bl_directory_lab.revoke_verified_entity_bound_lab_v2(
  '10000000-0000-4000-8000-000000000030',
  'Independent operator revokes outdated registry claim');
 IF got<>'entity_revoked_verified_endpoints_revoked'
 THEN RAISE EXCEPTION 'Bound revoker got unexpected result'; END IF;
END $revoke$;
RESET SESSION AUTHORIZATION;
DO $audit$
BEGIN
 IF (SELECT revoked_by FROM bl_directory_lab.issued_badges
     WHERE entity_id='10000000-0000-4000-8000-000000000030')
       IS DISTINCT FROM '33333333-3333-4333-8333-333333333333'::uuid
 OR (SELECT verification_status FROM public.entity_profiles
     WHERE id='10000000-0000-4000-8000-000000000030') <> 'revoked'
 OR (SELECT count(*) FROM bl_directory_lab.badge_events
     WHERE entity_id='10000000-0000-4000-8000-000000000030'
       AND actor_user_id='33333333-3333-4333-8333-333333333333'
       AND action='entity_revoked')<>1
 THEN RAISE EXCEPTION 'Revocation identity/event mismatch'; END IF;
END $audit$;
\echo 'PASS: Independent bound revoker records own session identity and immutable revocation event.'

UPDATE bl_directory_lab.db_operator_bindings
 SET active=false WHERE login_role='bl_lab_revoker';
SET SESSION AUTHORIZATION bl_lab_revoker;
DO $disabled_again$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.revoke_verified_entity_bound_lab_v2(
   '10000000-0000-4000-8000-000000000030',
   'Repeated revocation after operator deprovisioning');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Retired operator could access private action'; END IF;
END $disabled_again$;
RESET SESSION AUTHORIZATION;
\echo 'PASS: Deprovisioning immediately closes bound revocation path despite retained SQL role GRANT.'

DO $last$
BEGIN
 IF has_function_privilege('authenticated',
  'bl_directory_lab.issue_verified_entity_bound_lab_v2(uuid,timestamptz)',
  'EXECUTE')
 OR has_function_privilege('service_role',
  'bl_directory_lab.revoke_verified_entity_bound_lab_v2(uuid,text)',
  'EXECUTE')
 OR has_table_privilege('bl_lab_revoker',
  'bl_directory_lab.db_operator_bindings','UPDATE')
 THEN RAISE EXCEPTION 'Private operator role leaks direct privileged grants'; END IF;
END $last$;
\echo 'PASS: Private actor binding stays inaccessible to app roles and unprivileged operator sessions.'
