-- BHARATHLINK / REVIEW ONLY / DISPOSABLE PG16
-- Trusted-evidence + separate publication-preparation and revocation gate.
-- NO public Verified badge, no actual change to entity_profiles or endpoints.
-- NO real evidence provider integration, signature verification or reviewer
-- provisioning exists. These tables/functions are private lab candidates.
BEGIN;

CREATE TABLE bl_directory_lab.authority_attestations (
 request_id uuid PRIMARY KEY REFERENCES public.entity_verification_requests(id) ON DELETE RESTRICT,
 attested_by uuid NOT NULL,
 evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
 source_kind text NOT NULL CHECK (source_kind IN
   ('government_registry','regulated_registry','official_organization')),
 source_reference_sha256 text NOT NULL CHECK (source_reference_sha256 ~ '^[0-9a-f]{64}$'),
 attested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 expires_at timestamptz NOT NULL,
 CHECK (expires_at > attested_at)
);
ALTER TABLE bl_directory_lab.authority_attestations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.authority_attestations
 FROM PUBLIC,anon,authenticated,service_role;

-- Empty by default: no user can mint themselves as publisher by a client API.
CREATE TABLE bl_directory_lab.publisher_operators (
 user_id uuid PRIMARY KEY,
 provisioned_by uuid NOT NULL,
 active boolean NOT NULL DEFAULT false,
 country_code text NOT NULL DEFAULT 'IN',
 provisioned_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 CHECK (provisioned_by <> user_id)
);
ALTER TABLE bl_directory_lab.publisher_operators ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.publisher_operators
 FROM PUBLIC,anon,authenticated,service_role;

-- A private preparation ledger, NOT a published badge. A revoked
-- preparation cannot be silently reset; a fresh request is required.
CREATE TABLE bl_directory_lab.prepared_publications (
 request_id uuid PRIMARY KEY REFERENCES public.entity_verification_requests(id) ON DELETE RESTRICT,
 entity_id uuid NOT NULL REFERENCES public.entity_profiles(id) ON DELETE RESTRICT,
 evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
 prepared_by uuid NOT NULL,
 prepared_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','revoked')),
 revoked_by uuid,
 revoked_at timestamptz,
 revocation_reason text,
 CHECK (
   (state='prepared' AND revoked_by IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL)
   OR
   (state='revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL
      AND length(pg_catalog.btrim(revocation_reason)) BETWEEN 8 AND 500)
 )
);
ALTER TABLE bl_directory_lab.prepared_publications ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.prepared_publications
 FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl_directory_lab.publication_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id uuid NOT NULL REFERENCES public.entity_verification_requests(id) ON DELETE RESTRICT,
 actor_user_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('prepared','preparation_revoked')),
 happened_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 reason text
);
ALTER TABLE bl_directory_lab.publication_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.publication_events
 FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER publication_events_immutable
 BEFORE UPDATE OR DELETE ON bl_directory_lab.publication_events
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.reject_review_mutation();

-- Preparation requires TWO currently trusted distinct approvals to the
-- same evidence digest AND a different independent external attester.
-- It does NOT copy any status to public.entity_profiles.
CREATE OR REPLACE FUNCTION public.prepare_entity_publication_lab_v1(
 p_request_id uuid
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $prepare$
DECLARE
 v_actor uuid := (SELECT auth.uid());
 v_entity uuid;
 v_requester uuid;
 v_request_status text;
 v_creator uuid;
 v_country text;
 v_entity_status text;
 v_attester uuid;
 v_evidence text;
 v_attested_at timestamptz;
 v_expires timestamptz;
 v_approvals integer;
 v_bad_reviews integer;
BEGIN
 IF v_actor IS NULL OR p_request_id IS NULL THEN
  RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;
 SELECT r.entity_id,r.requester_user_id,r.status
 INTO v_entity,v_requester,v_request_status
 FROM public.entity_verification_requests r
 WHERE r.id=p_request_id FOR UPDATE;
 IF NOT FOUND OR v_request_status NOT IN ('pending','in_review') THEN
  RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;
 SELECT e.created_by,e.country_code,e.verification_status
 INTO v_creator,v_country,v_entity_status
 FROM public.entity_profiles e WHERE e.id=v_entity FOR UPDATE;
 IF NOT FOUND OR v_entity_status <> 'pending' THEN
  RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;

 IF v_actor IN (v_creator,v_requester)
   OR EXISTS(SELECT 1 FROM public.entity_authorized_users au
             WHERE au.entity_id=v_entity AND au.user_id=v_actor)
   OR NOT EXISTS(
     SELECT 1 FROM bl_directory_lab.publisher_operators op
     WHERE op.user_id=v_actor AND op.active=true
       AND op.country_code=v_country
       AND op.provisioned_by<>v_actor
   )
 THEN
   RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;

 SELECT a.attested_by,a.evidence_sha256,a.attested_at,a.expires_at
 INTO v_attester,v_evidence,v_attested_at,v_expires
 FROM bl_directory_lab.authority_attestations a
 WHERE a.request_id=p_request_id;
 IF NOT FOUND OR v_expires<=pg_catalog.clock_timestamp()
    OR v_attested_at>pg_catalog.clock_timestamp()
    OR v_actor=v_attester OR v_creator=v_attester OR v_requester=v_attester
    OR EXISTS(SELECT 1 FROM public.entity_authorized_users au
              WHERE au.entity_id=v_entity AND au.user_id=v_attester)
 THEN
  RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;

 -- If ANY review is rejected, tied to different evidence or signed by
 -- now-inactive reviewer, publication stays blocked.
 SELECT count(*) FILTER (
   WHERE d.decision='approve' AND d.evidence_sha256=v_evidence
     AND d.reviewer_user_id<>v_actor AND d.reviewer_user_id<>v_attester
     AND r.active=true AND r.provisioned_by<>r.user_id
 )::integer,
 count(*) FILTER (
   WHERE d.decision<>'approve' OR d.evidence_sha256<>v_evidence
     OR d.reviewer_user_id=v_actor OR d.reviewer_user_id=v_attester
     OR r.user_id IS NULL
     OR r.active IS DISTINCT FROM true
 )::integer
 INTO v_approvals,v_bad_reviews
 FROM bl_directory_lab.review_decisions d
 LEFT JOIN bl_directory_lab.approvers r ON r.user_id=d.reviewer_user_id
 WHERE d.request_id=p_request_id;

 IF v_approvals<>2 OR v_bad_reviews<>0 THEN
  RAISE EXCEPTION 'Publication preparation denied' USING ERRCODE='42501';
 END IF;

 INSERT INTO bl_directory_lab.prepared_publications(
   request_id,entity_id,evidence_sha256,prepared_by
 ) VALUES(p_request_id,v_entity,v_evidence,v_actor);
 INSERT INTO bl_directory_lab.publication_events(
   request_id,actor_user_id,action
 ) VALUES(p_request_id,v_actor,'prepared');

 RETURN 'prepared_no_public_verified_badge';
END;
$prepare$;

REVOKE ALL ON FUNCTION public.prepare_entity_publication_lab_v1(uuid)
 FROM PUBLIC,anon,authenticated,service_role;

-- Different live operator may revoke preparation. This is not the
-- final public badge revocation RPC; those semantics are NOT implemented.
CREATE OR REPLACE FUNCTION public.revoke_entity_publication_preparation_lab_v1(
 p_request_id uuid,
 p_reason text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $revoke$
DECLARE
 v_actor uuid := (SELECT auth.uid());
 v_prepared_by uuid;
 v_state text;
 v_entity uuid;
 v_country text;
 v_creator uuid;
 v_requester uuid;
BEGIN
 IF v_actor IS NULL OR p_request_id IS NULL OR p_reason IS NULL
   OR length(pg_catalog.btrim(p_reason)) NOT BETWEEN 8 AND 500 THEN
  RAISE EXCEPTION 'Publication revocation denied' USING ERRCODE='42501';
 END IF;

 SELECT pp.prepared_by,pp.state,pp.entity_id
 INTO v_prepared_by,v_state,v_entity
 FROM bl_directory_lab.prepared_publications pp
 WHERE pp.request_id=p_request_id FOR UPDATE;
 IF NOT FOUND OR v_state<>'prepared' THEN
  RAISE EXCEPTION 'Publication revocation denied' USING ERRCODE='42501';
 END IF;
 SELECT e.country_code,e.created_by
 INTO v_country,v_creator
 FROM public.entity_profiles e WHERE e.id=v_entity;
 SELECT vr.requester_user_id INTO v_requester
 FROM public.entity_verification_requests vr WHERE vr.id=p_request_id;
 IF v_actor IN (v_prepared_by,v_creator,v_requester)
   OR EXISTS(SELECT 1 FROM public.entity_authorized_users au
             WHERE au.entity_id=v_entity AND au.user_id=v_actor)
   OR NOT EXISTS(
      SELECT 1 FROM bl_directory_lab.publisher_operators op
      WHERE op.user_id=v_actor AND op.active=true
        AND op.country_code=v_country
   )
 THEN
   RAISE EXCEPTION 'Publication revocation denied' USING ERRCODE='42501';
 END IF;

 UPDATE bl_directory_lab.prepared_publications
 SET state='revoked',revoked_by=v_actor,
     revoked_at=pg_catalog.clock_timestamp(),
     revocation_reason=pg_catalog.btrim(p_reason)
 WHERE request_id=p_request_id AND state='prepared';

 INSERT INTO bl_directory_lab.publication_events(
  request_id,actor_user_id,action,reason
 ) VALUES(p_request_id,v_actor,'preparation_revoked',
          pg_catalog.btrim(p_reason));
 RETURN 'preparation_revoked_no_public_badge_change';
END;
$revoke$;

REVOKE ALL ON FUNCTION public.revoke_entity_publication_preparation_lab_v1(
 uuid,text
) FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
