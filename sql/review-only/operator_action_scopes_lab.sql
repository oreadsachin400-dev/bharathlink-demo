-- BHARATHLINK PRIVATE OPERATOR-SCOPE REGISTRY / REVIEW-ONLY PG16 LAB.
-- NEVER apply to active TEST/PROD; no operator verification or SSO exists.
BEGIN;
CREATE TABLE bl_directory_lab.operator_action_scopes (
 user_id uuid NOT NULL REFERENCES bl_directory_lab.publisher_operators(user_id)
   ON DELETE RESTRICT,
 action text NOT NULL CHECK(action IN ('issue','revoke')),
 granted_by uuid NOT NULL,
 granted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 active boolean NOT NULL DEFAULT true,
 revoked_at timestamptz,
 revoked_by uuid,
 PRIMARY KEY(user_id,action),
 CHECK (granted_by<>user_id),
 CHECK((active AND revoked_at IS NULL AND revoked_by IS NULL)
    OR (NOT active AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL
        AND revoked_by<>user_id))
);
ALTER TABLE bl_directory_lab.operator_action_scopes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.operator_action_scopes
 FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl_directory_lab.operator_scope_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('issue','revoke')),
 event text NOT NULL CHECK(event IN ('scope_granted','scope_revoked')),
 actor_user_id uuid NOT NULL,
 happened_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
ALTER TABLE bl_directory_lab.operator_scope_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.operator_scope_events
 FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER operator_scope_events_immutable
 BEFORE UPDATE OR DELETE ON bl_directory_lab.operator_scope_events
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.reject_review_mutation();

CREATE FUNCTION bl_directory_lab.guard_operator_scope()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path TO ''
AS $guard$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'Operator scope deletion denied' USING ERRCODE='42501';
 END IF;
 IF TG_OP='UPDATE' THEN
  IF NOT OLD.active OR NEW.user_id IS DISTINCT FROM OLD.user_id
   OR NEW.action IS DISTINCT FROM OLD.action
   OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
   OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
   OR NEW.active IS DISTINCT FROM false
   OR NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL
   OR NEW.revoked_by=NEW.user_id
  THEN RAISE EXCEPTION 'Operator scope mutation denied' USING ERRCODE='42501';
  END IF;
 END IF;
 RETURN NEW;
END;
$guard$;
CREATE TRIGGER guard_operator_scope_mutation
 BEFORE UPDATE OR DELETE ON bl_directory_lab.operator_action_scopes
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.guard_operator_scope();

CREATE FUNCTION bl_directory_lab.audit_operator_scope()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path TO ''
AS $audit$
BEGIN
 INSERT INTO bl_directory_lab.operator_scope_events(
   user_id,action,event,actor_user_id
 ) VALUES(NEW.user_id,NEW.action,
   CASE WHEN TG_OP='INSERT' THEN 'scope_granted' ELSE 'scope_revoked' END,
   CASE WHEN TG_OP='INSERT' THEN NEW.granted_by ELSE NEW.revoked_by END);
 RETURN NEW;
END;
$audit$;
CREATE TRIGGER audit_operator_scope_mutation
 AFTER INSERT OR UPDATE ON bl_directory_lab.operator_action_scopes
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.audit_operator_scope();
REVOKE ALL ON FUNCTION bl_directory_lab.guard_operator_scope(),
 bl_directory_lab.audit_operator_scope()
 FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
