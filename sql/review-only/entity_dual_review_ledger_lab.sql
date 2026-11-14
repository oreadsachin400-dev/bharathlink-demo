-- BHARATHLINK TRUST / REVIEW-ONLY / DISPOSABLE POSTGRESQL ONLY
-- No authority to create a public "Verified" badge. This is a proof-of-
-- review ledger, not a publishing/minting/verification endpoint.
-- NEVER apply to real TEST/PROD or grant client EXECUTE automatically.
BEGIN;

CREATE SCHEMA IF NOT EXISTS bl_directory_lab;
REVOKE ALL ON SCHEMA bl_directory_lab
  FROM PUBLIC,anon,authenticated,service_role;

-- Real service-side provisioning of reviewers is NOT implemented here.
-- Empty registry -> every approval attempt fails closed.
CREATE TABLE bl_directory_lab.approvers (
  user_id uuid PRIMARY KEY,
  active boolean NOT NULL DEFAULT false,
  country_code text NOT NULL DEFAULT 'IN' CHECK(country_code='IN'),
  scope_entity_type text NOT NULL DEFAULT 'all',
  provisioned_by uuid NOT NULL,
  provisioned_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE bl_directory_lab.approvers ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.approvers
  FROM PUBLIC,anon,authenticated,service_role;

-- Append-only evidence-review decisions, NEVER actual sensitive documents.
-- A SHA-256 evidence reference is NOT independent proof of authenticity.
CREATE TABLE bl_directory_lab.review_decisions (
  request_id uuid NOT NULL REFERENCES
    public.entity_verification_requests(id) ON DELETE RESTRICT,
  reviewer_user_id uuid NOT NULL,
  decision text NOT NULL CHECK(decision IN ('approve','reject')),
  evidence_sha256 text NOT NULL
    CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(request_id,reviewer_user_id)
);
ALTER TABLE bl_directory_lab.review_decisions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bl_directory_lab.review_decisions
  FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION bl_directory_lab.reject_review_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path TO '' AS $reject$
BEGIN
  RAISE EXCEPTION 'Review ledger is append-only'
    USING ERRCODE='42501';
END;
$reject$;
CREATE TRIGGER review_ledger_no_update
BEFORE UPDATE OR DELETE ON bl_directory_lab.review_decisions
FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.reject_review_mutation();

CREATE OR REPLACE FUNCTION public.record_entity_evidence_review_v1(
  p_request_id uuid,
  p_decision text,
  p_evidence_sha256 text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO ''
AS $review$
DECLARE
  v_reviewer uuid := (SELECT auth.uid());
  v_entity uuid;
  v_requester uuid;
  v_request_status text;
  v_creator uuid;
  v_country text;
  v_type text;
  v_entity_status text;
  v_review_count integer;
  v_distinct_hash_count integer;
  v_approvals integer;
  v_rejections integer;
BEGIN
  IF v_reviewer IS NULL OR p_request_id IS NULL
      OR p_decision NOT IN ('approve','reject')
      OR p_decision IS NULL
      OR p_evidence_sha256 IS NULL
      OR p_evidence_sha256 !~ '^[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'Evidence review denied' USING ERRCODE='42501';
  END IF;

  -- Serialize all decisions for this request so the second approver must
  -- observe the first, preventing double-approvals based on a stale view.
  SELECT vr.entity_id,vr.requester_user_id,vr.status
  INTO v_entity,v_requester,v_request_status
  FROM public.entity_verification_requests vr
  WHERE vr.id=p_request_id
  FOR UPDATE;
  IF NOT FOUND OR v_request_status NOT IN ('pending','in_review') THEN
    RAISE EXCEPTION 'Evidence review denied' USING ERRCODE='42501';
  END IF;

  SELECT e.created_by,e.country_code,e.entity_type,e.verification_status
  INTO v_creator,v_country,v_type,v_entity_status
  FROM public.entity_profiles e WHERE e.id=v_entity;
  IF NOT FOUND OR v_entity_status <> 'pending'
      OR v_creator=v_reviewer OR v_requester=v_reviewer THEN
    RAISE EXCEPTION 'Evidence review denied' USING ERRCODE='42501';
  END IF;

  -- A reviewer must be explicitly provisioned OFFLINE by trusted ops,
  -- and cannot be an owner/admin/representative of the same entity.
  IF NOT EXISTS (
    SELECT 1 FROM bl_directory_lab.approvers a
    WHERE a.user_id=v_reviewer AND a.active=true
      AND a.country_code=v_country
      AND (a.scope_entity_type='all' OR a.scope_entity_type=v_type)
      AND a.provisioned_by<>v_reviewer
  ) OR EXISTS (
    SELECT 1 FROM public.entity_authorized_users au
    WHERE au.entity_id=v_entity AND au.user_id=v_reviewer
  ) THEN
    RAISE EXCEPTION 'Evidence review denied' USING ERRCODE='42501';
  END IF;

  -- One irrevocable decision per reviewer / request: no flip-on-retry.
  INSERT INTO bl_directory_lab.review_decisions(
    request_id,reviewer_user_id,decision,evidence_sha256
  ) VALUES (p_request_id,v_reviewer,p_decision,p_evidence_sha256);

  SELECT count(*)::integer,
         count(DISTINCT evidence_sha256)::integer,
         count(*) FILTER (WHERE decision='approve')::integer,
         count(*) FILTER (WHERE decision='reject')::integer
    INTO v_review_count,v_distinct_hash_count,v_approvals,v_rejections
  FROM bl_directory_lab.review_decisions
  WHERE request_id=p_request_id;

  IF v_rejections>0 OR v_distinct_hash_count>1 THEN
    RETURN 'requires_independent_escalation';
  END IF;
  IF v_approvals>=2 AND v_review_count>=2 THEN
    -- NO UPDATE to public.entity_profiles verification_status.
    -- NO UPDATE to public.entity_endpoints.
    -- NO public Verified badge. A separate trusted publisher needs
    -- authoritative registry checks, document review and audit.
    RETURN 'two_reviews_recorded_publication_still_blocked';
  END IF;
  RETURN 'one_review_recorded';
END;
$review$;

REVOKE ALL ON FUNCTION public.record_entity_evidence_review_v1(
 uuid,text,text
) FROM PUBLIC,anon,authenticated,service_role;
COMMIT;
