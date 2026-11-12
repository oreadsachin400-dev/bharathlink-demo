\set ON_ERROR_STOP on
\echo 'ENTITY APPROVAL: independent review ledger / disposable PG16 only'

INSERT INTO public.entity_profiles(id,entity_type,legal_name,verification_status,
 created_by) VALUES
('10000000-0000-4000-8000-000000000012','business','Test Reviewer Owned Ltd',
 'pending','88888888-8888-4888-8888-888888888888'),
('10000000-0000-4000-8000-000000000013','business','Test Delegated Role Ltd',
 'pending','11111111-1111-4111-8111-111111111111');

INSERT INTO public.entity_authorized_users(entity_id,user_id,member_role) VALUES
('10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','owner'),
('10000000-0000-4000-8000-000000000013',
 '99999999-9999-4999-8999-999999999999','representative');

INSERT INTO public.entity_verification_requests
  (id,entity_id,requester_user_id,evidence_type,status) VALUES
('40000000-0000-4000-8000-000000000001',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000002',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000003',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000004',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','rejected'),
('40000000-0000-4000-8000-000000000005',
 '10000000-0000-4000-8000-000000000012',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000006',
 '10000000-0000-4000-8000-000000000002',
 '88888888-8888-4888-8888-888888888888','gstin','pending'),
('40000000-0000-4000-8000-000000000007',
 '10000000-0000-4000-8000-000000000013',
 '11111111-1111-4111-8111-111111111111','gstin','pending');

-- Review team only provisioned inside disposable lab.
-- A real operator registry does not exist on official TEST.
INSERT INTO bl_directory_lab.approvers(user_id,active,provisioned_by) VALUES
('88888888-8888-4888-8888-888888888888',true,
 '33333333-3333-4333-8333-333333333333'),
('99999999-9999-4999-8999-999999999999',true,
 '33333333-3333-4333-8333-333333333333'),
('77777777-7777-4777-8777-777777777777',false,
 '33333333-3333-4333-8333-333333333333'),
('55555555-5555-4555-8555-555555555555',true,
 '55555555-5555-4555-8555-555555555555');

SET ROLE anon;
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',
    repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Anonymous reviewer RPC enabled'; END IF;
END $deny$;
RESET ROLE;

SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',
    repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Unreleased reviewer API callable'; END IF;
 denied:=false;
 BEGIN PERFORM 1 FROM bl_directory_lab.review_decisions;
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Private audit ledger SELECT exposed'; END IF;
 denied:=false;
 BEGIN PERFORM 1 FROM bl_directory_lab.approvers;
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Trusted reviewer registry exposed'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Neither anonymous nor authenticated has direct review API or reviewer-ledger access.'

-- Temporary test-only API grant, not present in the review-only SQL.
GRANT EXECUTE ON FUNCTION public.record_entity_evidence_review_v1(uuid,text,text)
 TO authenticated;

-- Original entity owner and request submitter can never self-approve.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Entity owner self-approved'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Entity owner is not an authoritative verifier.'

SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000005','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Reviewer verified their own entity'; END IF;
 denied:=false;
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000006','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Reviewer approved their own request'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Even provisioned reviewers cannot approve own entity or own request.'

SET ROLE authenticated;
SET request.jwt.claim.sub='99999999-9999-4999-8999-999999999999';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000007','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Entity representative approved its claim'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Organization representatives cannot act as independent reviewers.'

SET ROLE authenticated;
SET request.jwt.claim.sub='77777777-7777-4777-8777-777777777777';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Inactive reviewer was accepted'; END IF;
END $bad$;
RESET ROLE;

SET ROLE authenticated;
SET request.jwt.claim.sub='55555555-5555-4555-8555-555555555555';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Self-provisioned reviewer was accepted'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Inactive and self-provisioned reviewer accounts are rejected.'

SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
DO $review$
DECLARE v_status text;denied boolean:=false;
BEGIN
 v_status:=public.record_entity_evidence_review_v1(
   '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 IF v_status<>'one_review_recorded' THEN
  RAISE EXCEPTION 'First independent approval marked request published';
 END IF;
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 EXCEPTION WHEN unique_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Same reviewer approved request twice'; END IF;
END $review$;
RESET ROLE;
\echo 'PASS: One review is insufficient, identical reviewer cannot double-approve.'

SET ROLE authenticated;
SET request.jwt.claim.sub='99999999-9999-4999-8999-999999999999';
DO $second$
DECLARE result text;
BEGIN
 result:=public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve',repeat('a',64));
 IF result<>'two_reviews_recorded_publication_still_blocked' THEN
  RAISE EXCEPTION 'Two independent approvals did not reach review-only state';
 END IF;
END $second$;
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT count(*) FROM bl_directory_lab.review_decisions
   WHERE request_id='40000000-0000-4000-8000-000000000001')<>2 THEN
  RAISE EXCEPTION 'Two-review ledger entries missing';
 END IF;
 IF (SELECT verification_status FROM public.entity_profiles
   WHERE id='10000000-0000-4000-8000-000000000002')<>'pending' THEN
  RAISE EXCEPTION 'Two reviews improperly minted a Verified entity badge';
 END IF;
 IF (SELECT status FROM public.entity_verification_requests
   WHERE id='40000000-0000-4000-8000-000000000001')<>'pending' THEN
  RAISE EXCEPTION 'Review-only candidate changed public request status';
 END IF;
END $check$;
\echo 'PASS: Two independent reviews recorded but public verification status remains pending.'

SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
SELECT public.record_entity_evidence_review_v1(
 '40000000-0000-4000-8000-000000000002','approve',
 repeat('b',64)) AS reviewer_one;
SELECT public.record_entity_evidence_review_v1(
 '40000000-0000-4000-8000-000000000003','approve',
 repeat('c',64)) AS reviewer_one_other;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='99999999-9999-4999-8999-999999999999';
DO $conflict$
DECLARE d text;hash_conflict text;
BEGIN
 d:=public.record_entity_evidence_review_v1(
  '40000000-0000-4000-8000-000000000002','reject',repeat('b',64));
 hash_conflict:=public.record_entity_evidence_review_v1(
  '40000000-0000-4000-8000-000000000003','approve',repeat('d',64));
 IF d<>'requires_independent_escalation' OR
    hash_conflict<>'requires_independent_escalation' THEN
  RAISE EXCEPTION 'Conflicting independent evidence/reviews silently approved';
 END IF;
END $conflict$;
RESET ROLE;
\echo 'PASS: Reviewer disagreement and mismatched evidence hashes require escalation.'

SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000004','approve',repeat('a',64));
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Rejected request reviewed again'; END IF;
 denied:=false;
 BEGIN
  PERFORM public.record_entity_evidence_review_v1(
    '40000000-0000-4000-8000-000000000001','approve','not-a-digest');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Bad evidence hash accepted'; END IF;
END $bad$;
RESET ROLE;
\echo 'PASS: Closed request and invalid evidence digest are rejected.'

DO $immutable$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  UPDATE bl_directory_lab.review_decisions SET decision='reject'
   WHERE request_id='40000000-0000-4000-8000-000000000001';
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Review audit was mutable'; END IF;
 denied:=false;
 BEGIN
  DELETE FROM bl_directory_lab.review_decisions
   WHERE request_id='40000000-0000-4000-8000-000000000001';
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Review audit could be deleted'; END IF;
END $immutable$;
\echo 'PASS: Ledger cannot be UPDATEd/DELETEd even by its owning role.'

REVOKE EXECUTE ON FUNCTION public.record_entity_evidence_review_v1(uuid,text,text)
 FROM authenticated;
DO $guard$
BEGIN
 IF has_function_privilege('authenticated',
  'public.record_entity_evidence_review_v1(uuid,text,text)','EXECUTE') THEN
  RAISE EXCEPTION 'Review RPC accidentally left enabled';
 END IF;
END $guard$;
\echo 'PASS: Review API client EXECUTE remains denied after tests.'
