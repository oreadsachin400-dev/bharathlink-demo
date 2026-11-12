-- BHARATHLINK TRUST / FINAL BADGE STATE MACHINE / REVIEW-ONLY PG16 LAB.
-- DO NOT APPLY TO ACTIVE TEST/PROD. No public/data-API RPCs, no GRANTs.
-- Private, SECURITY INVOKER functions exercise a *hypothetical trusted
-- backoffice* transaction. This is NOT an operator-authentication service.
-- The caller-supplied actor UUID must be independently authenticated in a
-- future dedicated service. DO NOT expose these signatures as RPC routes.
BEGIN;

CREATE TABLE bl_directory_lab.issued_badges (
  entity_id uuid PRIMARY KEY REFERENCES public.entity_profiles(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL UNIQUE
    REFERENCES public.entity_verification_requests(id) ON DELETE RESTRICT,
  source_reference_sha256 text NOT NULL UNIQUE
    CHECK(source_reference_sha256 ~ '^[0-9a-f]{64}$'),
  evidence_sha256 text NOT NULL
    CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
  issued_by uuid NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK(state IN ('verified','revoked')),
  revoked_by uuid,
  revoked_at timestamptz,
  revocation_reason text,
  CHECK (
    (state='verified' AND revoked_by IS NULL AND revoked_at IS NULL
       AND revocation_reason IS NULL)
    OR (state='revoked' AND revoked_by IS NOT NULL
       AND revoked_at IS NOT NULL
       AND length(pg_catalog.btrim(revocation_reason)) BETWEEN 8 AND 500)
  )
);
ALTER TABLE bl_directory_lab.issued_badges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.issued_badges
  FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE bl_directory_lab.badge_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  entity_id uuid NOT NULL REFERENCES public.entity_profiles(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL REFERENCES public.entity_verification_requests(id) ON DELETE RESTRICT,
  action text NOT NULL CHECK (action IN
    ('entity_verified','entity_revoked','endpoint_cascade_revoked')),
  actor_user_id uuid NOT NULL,
  happened_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  endpoint_id uuid,
  reason text
);
ALTER TABLE bl_directory_lab.badge_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.badge_events
  FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER badge_events_immutable
  BEFORE UPDATE OR DELETE ON bl_directory_lab.badge_events
  FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.reject_review_mutation();

-- Strictly INTERNAL service-only issue. Not SECURITY DEFINER, so it never
-- acquires privileges from an RPC caller. In the lab only postgres can run.
-- Revalidate all prior evidence at issuance, not only when prepared.
CREATE FUNCTION bl_directory_lab.issue_verified_entity_lab_v1(
  p_request_id uuid, p_actor uuid, p_valid_until timestamptz
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path TO ''
AS $issue$
DECLARE
 v_entity uuid; v_requester uuid; v_request_status text;
 v_creator uuid; v_country text; v_type text; v_status text;
 v_preparer uuid; v_prepared_at timestamptz; v_evidence text;
 v_attester uuid; v_attest_evidence text; v_attest_expiry timestamptz;
 v_attest_at timestamptz; v_source text;
 v_approvals integer; v_bad_reviews integer;
 v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
 IF current_user <> 'postgres' OR p_request_id IS NULL OR p_actor IS NULL
   OR p_valid_until IS NULL OR p_valid_until <= v_now
   OR p_valid_until > v_now + interval '90 days'
 THEN RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501'; END IF;

 SELECT vr.entity_id,vr.requester_user_id,vr.status
 INTO v_entity,v_requester,v_request_status
 FROM public.entity_verification_requests vr
 WHERE vr.id=p_request_id FOR UPDATE;
 IF NOT FOUND OR v_request_status NOT IN ('pending','in_review') THEN
  RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501';
 END IF;

 SELECT e.created_by,e.country_code,e.entity_type,e.verification_status
 INTO v_creator,v_country,v_type,v_status
 FROM public.entity_profiles e WHERE e.id=v_entity FOR UPDATE;
 IF NOT FOUND OR v_status <> 'pending' THEN
  RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501';
 END IF;

 SELECT pp.prepared_by,pp.prepared_at,pp.evidence_sha256
 INTO v_preparer,v_prepared_at,v_evidence
 FROM bl_directory_lab.prepared_publications pp
 WHERE pp.request_id=p_request_id AND pp.entity_id=v_entity
   AND pp.state='prepared' FOR UPDATE;
 IF NOT FOUND OR v_prepared_at>v_now
    OR v_prepared_at < v_now-interval '7 days'
 THEN RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501'; END IF;

 IF p_actor IN (v_creator,v_requester,v_preparer)
   OR EXISTS (SELECT 1 FROM public.entity_authorized_users au
              WHERE au.entity_id=v_entity AND au.user_id=p_actor)
   OR NOT EXISTS (
     SELECT 1 FROM bl_directory_lab.publisher_operators op
     WHERE op.user_id=p_actor AND op.active AND op.country_code=v_country
       AND op.provisioned_by<>p_actor
   )
 THEN RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501'; END IF;

 SELECT a.attested_by,a.evidence_sha256,a.source_reference_sha256,
        a.attested_at,a.expires_at
 INTO v_attester,v_attest_evidence,v_source,v_attest_at,v_attest_expiry
 FROM bl_directory_lab.authority_attestations a
 WHERE a.request_id=p_request_id;
 IF NOT FOUND OR v_attest_evidence<>v_evidence
    OR v_attest_expiry<=v_now OR v_attest_expiry<p_valid_until
    OR v_attest_at>v_now
    OR p_actor=v_attester OR v_attester IN (v_creator,v_requester,v_preparer)
    OR EXISTS(SELECT 1 FROM public.entity_authorized_users au
      WHERE au.entity_id=v_entity AND au.user_id=v_attester)
 THEN RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501'; END IF;

 SELECT count(*) FILTER(
     WHERE d.decision='approve' AND d.evidence_sha256=v_evidence
       AND d.reviewer_user_id NOT IN (p_actor,v_preparer,v_attester,v_creator,v_requester)
       AND ap.active=true AND ap.country_code=v_country
       AND ap.provisioned_by<>ap.user_id
       AND (ap.scope_entity_type='all' OR ap.scope_entity_type=v_type)
 )::integer,
 count(*) FILTER (
     WHERE d.decision<>'approve' OR d.evidence_sha256<>v_evidence
       OR d.reviewer_user_id IN (p_actor,v_preparer,v_attester,v_creator,v_requester)
       OR ap.user_id IS NULL OR ap.active IS DISTINCT FROM true
       OR ap.country_code IS DISTINCT FROM v_country
       OR NOT (ap.scope_entity_type='all' OR ap.scope_entity_type=v_type)
 )::integer
 INTO v_approvals,v_bad_reviews
 FROM bl_directory_lab.review_decisions d
 LEFT JOIN bl_directory_lab.approvers ap ON ap.user_id=d.reviewer_user_id
 WHERE d.request_id=p_request_id;
 IF v_approvals<>2 OR v_bad_reviews<>0 THEN
  RAISE EXCEPTION 'Trusted entity issuance denied' USING ERRCODE='42501';
 END IF;

 -- UNIQUE(source_reference_sha256) is deliberately permanent, including
 -- revoked rows: never silently reassign a previous official identity.
 INSERT INTO bl_directory_lab.issued_badges (
   entity_id,request_id,source_reference_sha256,evidence_sha256,
   issued_by,issued_at,expires_at,state
 ) VALUES (
   v_entity,p_request_id,v_source,v_evidence,p_actor,v_now,p_valid_until,'verified'
 );

 UPDATE public.entity_profiles
 SET verification_status='verified',
     verification_method='independent_authority_review',
     verified_at=v_now,verification_expires_at=p_valid_until
 WHERE id=v_entity AND verification_status='pending';
 IF NOT FOUND THEN
  RAISE EXCEPTION 'Trusted entity issuance changed concurrently'
    USING ERRCODE='40001';
 END IF;

 UPDATE public.entity_verification_requests
 SET status='approved',reviewed_at=v_now WHERE id=p_request_id;

 INSERT INTO bl_directory_lab.badge_events(
   entity_id,request_id,action,actor_user_id
 ) VALUES(v_entity,p_request_id,'entity_verified',p_actor);
 -- Endpoint status deliberately NOT modified. Every phone/mail endpoint
 -- needs separate proof and release. No owner receives a free verified phone.
 RETURN 'entity_verified_endpoint_status_unchanged';
END;
$issue$;

REVOKE ALL ON FUNCTION bl_directory_lab.issue_verified_entity_lab_v1(
 uuid,uuid,timestamptz
) FROM PUBLIC,anon,authenticated,service_role;

-- Strictly INTERNAL service-only revocation, independent of issuer.
-- Revokes any already verified/suspended endpoint of the same entity,
-- in the SAME transaction, so alternate endpoint-only reads cannot
-- mistakenly keep claiming a currently revoked organization.
CREATE FUNCTION bl_directory_lab.revoke_verified_entity_lab_v1(
 p_entity_id uuid,p_actor uuid,p_reason text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path TO ''
AS $revoke$
DECLARE
 v_now timestamptz := pg_catalog.clock_timestamp();
 v_issuer uuid; v_request uuid; v_country text;
 v_creator uuid; v_requester uuid; v_preparer uuid;
 v_id uuid;
BEGIN
 IF current_user<>'postgres' OR p_entity_id IS NULL OR p_actor IS NULL
   OR p_reason IS NULL OR length(pg_catalog.btrim(p_reason)) NOT BETWEEN 8 AND 500
 THEN RAISE EXCEPTION 'Trusted revocation denied' USING ERRCODE='42501'; END IF;

 SELECT b.issued_by,b.request_id INTO v_issuer,v_request
 FROM bl_directory_lab.issued_badges b
 WHERE b.entity_id=p_entity_id AND b.state='verified' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Trusted revocation denied' USING ERRCODE='42501'; END IF;
 SELECT e.country_code,e.created_by INTO v_country,v_creator
 FROM public.entity_profiles e WHERE e.id=p_entity_id FOR UPDATE;
 SELECT vr.requester_user_id INTO v_requester
 FROM public.entity_verification_requests vr WHERE vr.id=v_request;
 SELECT pp.prepared_by INTO v_preparer
 FROM bl_directory_lab.prepared_publications pp WHERE pp.request_id=v_request;

 IF p_actor IN (v_issuer,v_creator,v_requester,v_preparer)
   OR EXISTS (SELECT 1 FROM public.entity_authorized_users au
      WHERE au.entity_id=p_entity_id AND au.user_id=p_actor)
   OR NOT EXISTS (
     SELECT 1 FROM bl_directory_lab.publisher_operators op
     WHERE op.user_id=p_actor AND op.active
       AND op.country_code=v_country AND op.provisioned_by<>p_actor
   )
 THEN RAISE EXCEPTION 'Trusted revocation denied' USING ERRCODE='42501'; END IF;

 UPDATE bl_directory_lab.issued_badges
 SET state='revoked',revoked_by=p_actor,revoked_at=v_now,
     revocation_reason=pg_catalog.btrim(p_reason)
 WHERE entity_id=p_entity_id AND state='verified';
 UPDATE public.entity_profiles
 SET verification_status='revoked',verification_expires_at=v_now
 WHERE id=p_entity_id AND verification_status='verified';
 IF NOT FOUND THEN RAISE EXCEPTION 'Entity state changed before revocation'
   USING ERRCODE='40001'; END IF;

 FOR v_id IN
   SELECT ep.id FROM public.entity_endpoints ep
   WHERE ep.entity_id=p_entity_id AND ep.verification_status IN ('verified','suspended')
   ORDER BY ep.id FOR UPDATE
 LOOP
   UPDATE public.entity_endpoints
   SET verification_status='revoked',revoked_at=v_now,
       revocation_reason=pg_catalog.btrim(p_reason)
   WHERE id=v_id AND verification_status IN ('verified','suspended');
   INSERT INTO bl_directory_lab.badge_events(
     entity_id,request_id,action,actor_user_id,endpoint_id,reason
   ) VALUES(p_entity_id,v_request,'endpoint_cascade_revoked',
       p_actor,v_id,pg_catalog.btrim(p_reason));
 END LOOP;

 INSERT INTO bl_directory_lab.badge_events(
   entity_id,request_id,action,actor_user_id,reason
 ) VALUES(p_entity_id,v_request,'entity_revoked',
          p_actor,pg_catalog.btrim(p_reason));
 RETURN 'entity_revoked_verified_endpoints_revoked';
END;
$revoke$;

REVOKE ALL ON FUNCTION bl_directory_lab.revoke_verified_entity_lab_v1(
 uuid,uuid,text
) FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
