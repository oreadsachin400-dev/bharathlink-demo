-- BHARATHLINK REVIEW-ONLY / PG16 OPERATOR DB LOGIN BINDING LAB.
-- NOT a Supabase migration. DO NOT install in active TEST or PROD.
-- A distinct authenticated PostgreSQL login is simulated by CI's
-- SET SESSION AUTHORIZATION; no real SSO/MFA, credentials or registry exist.
-- Security boundary: actor is derived from session_user + an admin-provisioned
-- mapping, never from a request parameter/JWT claim. No public API grants.
BEGIN;

CREATE TABLE bl_directory_lab.db_operator_bindings (
  login_role name PRIMARY KEY,
  actor_user_id uuid NOT NULL UNIQUE
    REFERENCES bl_directory_lab.publisher_operators(user_id)
      ON DELETE RESTRICT,
  permission text NOT NULL CHECK(permission IN ('issue','revoke')),
  active boolean NOT NULL DEFAULT false,
  provisioned_by uuid NOT NULL,
  bound_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  CHECK(provisioned_by<>actor_user_id)
);
ALTER TABLE bl_directory_lab.db_operator_bindings ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.db_operator_bindings
 FROM PUBLIC,anon,authenticated,service_role;

-- Only the private wrapper may cross into the older service executor.
-- Although SECURITY DEFINER is necessary for this isolated bridge, it
-- is dangerous if exposed: fixed search_path, qualified objects, explicit
-- default-deny grants, no client JWT impersonation and no actor UUID arg.
CREATE FUNCTION bl_directory_lab.issue_verified_entity_bound_lab_v2(
 p_request_id uuid,p_valid_until timestamptz
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $bound_issue$
DECLARE v_actor uuid;
BEGIN
 SELECT b.actor_user_id INTO v_actor
 FROM bl_directory_lab.db_operator_bindings b
 JOIN bl_directory_lab.publisher_operators po
   ON po.user_id=b.actor_user_id
 JOIN pg_catalog.pg_roles dbrole
   ON dbrole.rolname=b.login_role
 WHERE b.login_role=session_user::name
   AND b.active AND b.permission='issue'
   AND po.active AND po.provisioned_by<>po.user_id
   AND dbrole.rolcanlogin AND NOT dbrole.rolsuper
   AND NOT dbrole.rolbypassrls AND NOT dbrole.rolcreaterole;
 IF v_actor IS NULL THEN
  RAISE EXCEPTION 'Trusted issuer login not bound or disabled'
    USING ERRCODE='42501';
 END IF;
 RETURN bl_directory_lab.issue_verified_entity_lab_v1(
   p_request_id,v_actor,p_valid_until);
END;
$bound_issue$;
REVOKE ALL ON FUNCTION bl_directory_lab.issue_verified_entity_bound_lab_v2(
 uuid,timestamptz
) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION bl_directory_lab.revoke_verified_entity_bound_lab_v2(
 p_entity_id uuid,p_reason text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $bound_revoke$
DECLARE v_actor uuid;
BEGIN
 SELECT b.actor_user_id INTO v_actor
 FROM bl_directory_lab.db_operator_bindings b
 JOIN bl_directory_lab.publisher_operators po
   ON po.user_id=b.actor_user_id
 JOIN pg_catalog.pg_roles dbrole
   ON dbrole.rolname=b.login_role
 WHERE b.login_role=session_user::name
   AND b.active AND b.permission='revoke'
   AND po.active AND po.provisioned_by<>po.user_id
   AND dbrole.rolcanlogin AND NOT dbrole.rolsuper
   AND NOT dbrole.rolbypassrls AND NOT dbrole.rolcreaterole;
 IF v_actor IS NULL THEN
  RAISE EXCEPTION 'Trusted revoker login not bound or disabled'
    USING ERRCODE='42501';
 END IF;
 RETURN bl_directory_lab.revoke_verified_entity_lab_v1(
   p_entity_id,v_actor,p_reason);
END;
$bound_revoke$;
REVOKE ALL ON FUNCTION bl_directory_lab.revoke_verified_entity_bound_lab_v2(
 uuid,text
) FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
