\set ON_ERROR_STOP on
\echo 'ENTITY PUBLICATION PREPARATION: synthetic only, never a public badge'

-- Existing dual review fixture has two matching independent approvals for
-- request 001 on SHA256('a...' fixture). Entirely synthetic test principals.
INSERT INTO bl_directory_lab.publisher_operators(
 user_id,provisioned_by,active
) VALUES
('66666666-6666-4666-8666-666666666666',
 '33333333-3333-4333-8333-333333333333',true),
('44444444-4444-4444-8444-444444444444',
 '33333333-3333-4333-8333-333333333333',true),
('77777777-7777-4777-8777-777777777777',
 '33333333-3333-4333-8333-333333333333',false);

INSERT INTO bl_directory_lab.authority_attestations(
 request_id,attested_by,evidence_sha256,source_kind,
 source_reference_sha256,expires_at
) VALUES
('40000000-0000-4000-8000-000000000001',
 '22222222-2222-4222-8222-222222222222',
 repeat('a',64),'government_registry',repeat('f',64),
 clock_timestamp()+interval '90 days'),
('40000000-0000-4000-8000-000000000002',
 '22222222-2222-4222-8222-222222222222',
 repeat('b',64),'regulated_registry',repeat('e',64),
 clock_timestamp()+interval '90 days'),
('40000000-0000-4000-8000-000000000003',
 '22222222-2222-4222-8222-222222222222',
 repeat('c',64),'regulated_registry',repeat('e',64),
 clock_timestamp()+interval '90 days');

-- The evidence table and preparatory function are not app-accessible.
SET ROLE anon;
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Anonymous can prepare Verified badge'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $deny$
DECLARE denied boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Release-blocked preparation is callable'; END IF;
 denied:=false;
 BEGIN PERFORM public.revoke_entity_publication_preparation_lab_v1(
  '40000000-0000-4000-8000-000000000001','Manual revocation');
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Release-blocked revoke is callable'; END IF;
 denied:=false;
 BEGIN PERFORM 1 FROM bl_directory_lab.authority_attestations;
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Authority evidence table exposed'; END IF;
 denied:=false;
 BEGIN PERFORM 1 FROM bl_directory_lab.publisher_operators;
 EXCEPTION WHEN insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Publisher registry exposed'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Client roles cannot access private attestations/registry or release-gated RPCs.'

-- Grant ONLY inside ephemeral PG16 to test defensive contract.
GRANT EXECUTE ON FUNCTION public.prepare_entity_publication_lab_v1(uuid)
 TO authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_entity_publication_preparation_lab_v1(uuid,text)
 TO authenticated;

SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Request owner prepared own publication'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='88888888-8888-4888-8888-888888888888';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Reviewer prepared publication'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='77777777-7777-4777-8777-777777777777';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Inactive publisher prepared publication'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Requester, reviewer and inactive publisher cannot prepare publication.'

-- Reviewer disagreement and evidence hash mismatch stay on HOLD.
SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000002');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Reviewer disagreement accepted'; END IF;
 blocked:=false;
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000003');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Mismatched evidence accepted'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Review disagreement or changed evidence cannot prepare public trust.'

-- Attach valid reviewed synthetic request with an expired attestation.
INSERT INTO public.entity_verification_requests(
 id,entity_id,requester_user_id,evidence_type,status
) VALUES
('40000000-0000-4000-8000-000000000010',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000011',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending'),
('40000000-0000-4000-8000-000000000012',
 '10000000-0000-4000-8000-000000000002',
 '11111111-1111-4111-8111-111111111111','gstin','pending');
INSERT INTO bl_directory_lab.review_decisions(
 request_id,reviewer_user_id,decision,evidence_sha256
)
SELECT r.req,rv.reviewer,'approve',repeat('d',64)
FROM (VALUES
 ('40000000-0000-4000-8000-000000000010'::uuid),
 ('40000000-0000-4000-8000-000000000011'::uuid),
 ('40000000-0000-4000-8000-000000000012'::uuid)
) r(req) CROSS JOIN (VALUES
 ('88888888-8888-4888-8888-888888888888'::uuid),
 ('99999999-9999-4999-8999-999999999999'::uuid)
) rv(reviewer);
INSERT INTO bl_directory_lab.authority_attestations(
 request_id,attested_by,evidence_sha256,source_kind,source_reference_sha256,
 attested_at,expires_at
) VALUES
('40000000-0000-4000-8000-000000000010',
 '22222222-2222-4222-8222-222222222222',
 repeat('d',64),'government_registry',repeat('e',64),
 clock_timestamp()-interval '10 days',clock_timestamp()-interval '1 day'),
('40000000-0000-4000-8000-000000000011',
 '22222222-2222-4222-8222-222222222222',
 repeat('e',64),'government_registry',repeat('e',64),
 clock_timestamp()-interval '1 day',clock_timestamp()+interval '5 days'),
('40000000-0000-4000-8000-000000000012',
 '66666666-6666-4666-8666-666666666666',
 repeat('d',64),'government_registry',repeat('e',64),
 clock_timestamp()-interval '1 day',clock_timestamp()+interval '5 days');

SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000010');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Expired authority attestation accepted'; END IF;
 blocked:=false;
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000011');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Mismatched authority digest accepted'; END IF;
 blocked:=false;
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000012');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Publisher self-attestation accepted'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Expired evidence, hash mismatch and self-attestation fail closed.'

-- Successful preparation is only private: never set public verification.
SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $prepare$
DECLARE result text;blocked boolean:=false;
BEGIN
 result:=public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 IF result<>'prepared_no_public_verified_badge' THEN
  RAISE EXCEPTION 'Unexpected preparation result'; END IF;
 BEGIN
  PERFORM public.prepare_entity_publication_lab_v1(
   '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN unique_violation THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Repeated preparation succeeded'; END IF;
END $prepare$;
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT state FROM bl_directory_lab.prepared_publications
  WHERE request_id='40000000-0000-4000-8000-000000000001')<>'prepared'
  OR (SELECT count(*) FROM bl_directory_lab.publication_events
    WHERE request_id='40000000-0000-4000-8000-000000000001')<>1 THEN
  RAISE EXCEPTION 'Prepared ledger/event missing'; END IF;
 IF (SELECT verification_status FROM public.entity_profiles
   WHERE id='10000000-0000-4000-8000-000000000002')<>'pending' THEN
  RAISE EXCEPTION 'Preparation minted public Verified status'; END IF;
 IF (SELECT status FROM public.entity_verification_requests
   WHERE id='40000000-0000-4000-8000-000000000001')<>'pending' THEN
  RAISE EXCEPTION 'Preparation altered official review status'; END IF;
END $check$;
\echo 'PASS: Two independent approvals + separate attestation allow PRIVATE preparation only.'

-- Revocation needs different authorized operator, reason and one-shot state.
SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.revoke_entity_publication_preparation_lab_v1(
  '40000000-0000-4000-8000-000000000001','Request withdrawn by reviewer');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Preparing publisher revoked own record'; END IF;
END $deny$;
RESET ROLE;
SET ROLE authenticated;
SET request.jwt.claim.sub='44444444-4444-4444-8444-444444444444';
DO $revoke$
DECLARE answer text;blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.revoke_entity_publication_preparation_lab_v1(
  '40000000-0000-4000-8000-000000000001','short');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Short revocation reason accepted'; END IF;
 answer:=public.revoke_entity_publication_preparation_lab_v1(
  '40000000-0000-4000-8000-000000000001',
  'Separate operator cancelled publication preparation');
 IF answer<>'preparation_revoked_no_public_badge_change' THEN
  RAISE EXCEPTION 'Wrong private revocation response'; END IF;
 blocked:=false;
 BEGIN PERFORM public.revoke_entity_publication_preparation_lab_v1(
  '40000000-0000-4000-8000-000000000001','Repeated revocation not allowed');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Repeated revocation succeeded'; END IF;
END $revoke$;
RESET ROLE;
DO $check$
BEGIN
 IF (SELECT state FROM bl_directory_lab.prepared_publications
   WHERE request_id='40000000-0000-4000-8000-000000000001')<>'revoked'
 OR (SELECT count(*) FROM bl_directory_lab.publication_events
   WHERE request_id='40000000-0000-4000-8000-000000000001')<>2
 THEN RAISE EXCEPTION 'Revocation state/event mismatch'; END IF;
 IF (SELECT verification_status FROM public.entity_profiles
   WHERE id='10000000-0000-4000-8000-000000000002')<>'pending' THEN
  RAISE EXCEPTION 'Private revocation affected public verification'; END IF;
END $check$;
\echo 'PASS: Different authorized operator revokes preparation with immutable event; no badge.'

SET ROLE authenticated;
SET request.jwt.claim.sub='66666666-6666-4666-8666-666666666666';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.prepare_entity_publication_lab_v1(
  '40000000-0000-4000-8000-000000000001');
 EXCEPTION WHEN unique_violation THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Revoked preparation was silently re-armed'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: Revoked preparation cannot be silently restored for same request.'

DO $immutable$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  UPDATE bl_directory_lab.publication_events SET action='prepared'
  WHERE request_id='40000000-0000-4000-8000-000000000001';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Publication audit event mutable'; END IF;
 blocked:=false;
 BEGIN
  DELETE FROM bl_directory_lab.publication_events
  WHERE request_id='40000000-0000-4000-8000-000000000001';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Publication event deletion allowed'; END IF;
END $immutable$;
\echo 'PASS: Publication-preparation audit events append-only even for DB owner.'

REVOKE EXECUTE ON FUNCTION public.prepare_entity_publication_lab_v1(uuid)
 FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.revoke_entity_publication_preparation_lab_v1(uuid,text)
 FROM authenticated;
DO $guard$
BEGIN
 IF has_function_privilege('authenticated',
  'public.prepare_entity_publication_lab_v1(uuid)','EXECUTE')
 OR has_function_privilege('authenticated',
  'public.revoke_entity_publication_preparation_lab_v1(uuid,text)','EXECUTE')
 THEN
  RAISE EXCEPTION 'Client still has private publication preparation rights';
 END IF;
END $guard$;
\echo 'PASS: Final client permissions remain denied for private publish/revoke.'
