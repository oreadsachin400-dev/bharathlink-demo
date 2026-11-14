\set ON_ERROR_STOP on
\echo 'INTERNAL BADGE ISSUE/REVOKE — synthetic service-only PG16'

-- Official TEST verification triggers and audit columns were installed in the
-- separate disposable PG16 step; only synthetic users/records follow here.
-- A new synthetic, pending organization and request (not the revoked
-- preparation from earlier tests). All actor UUIDs are fake.
INSERT INTO public.entity_profiles(
  id,entity_type,legal_name,display_name,verification_status,
  created_by,country_code
) VALUES (
 '10000000-0000-4000-8000-000000000020','business','Lab Registry 20 Ltd',
 'Lab Registry 20','pending','11111111-1111-4111-8111-111111111111','IN'
);
INSERT INTO public.entity_verification_requests(
  id,entity_id,requester_user_id,evidence_type,status
) VALUES (
 '40000000-0000-4000-8000-000000000020',
 '10000000-0000-4000-8000-000000000020',
 '11111111-1111-4111-8111-111111111111','gstin','pending'
);
INSERT INTO public.entity_endpoints(
 id,entity_id,endpoint_type,endpoint_value,display_value,
 verification_status,verified_at
) VALUES
('20000000-0000-4000-8000-000000000020',
 '10000000-0000-4000-8000-000000000020',
 'mobile','9000000020','+91 90000 00020','pending',NULL);

-- Check actual TEST trigger bodies with a simulated JWT role. This uses
-- postgres only to exercise trigger logic; it does not emulate grants/RLS.
DO $trigger_compat$
DECLARE entity_denied boolean:=false; endpoint_denied boolean:=false;
BEGIN
 PERFORM pg_catalog.set_config('request.jwt.claim.role','authenticated',true);
 BEGIN
  UPDATE public.entity_profiles SET verification_status='verified'
  WHERE id='10000000-0000-4000-8000-000000000020';
 EXCEPTION WHEN others THEN
  IF SQLERRM='Entity verification fields are server-authoritative'
  THEN entity_denied:=true; ELSE RAISE; END IF;
 END;
 BEGIN
  UPDATE public.entity_endpoints SET verification_status='verified'
  WHERE id='20000000-0000-4000-8000-000000000020';
 EXCEPTION WHEN others THEN
  IF SQLERRM='Endpoint verification fields are server-authoritative'
  THEN endpoint_denied:=true; ELSE RAISE; END IF;
 END;
 IF NOT entity_denied OR NOT endpoint_denied
 THEN RAISE EXCEPTION 'Real TEST verification trigger permitted client-style status mutation'; END IF;
 IF (SELECT verification_status FROM public.entity_profiles
     WHERE id='10000000-0000-4000-8000-000000000020')<>'pending'
 OR (SELECT verification_status FROM public.entity_endpoints
     WHERE id='20000000-0000-4000-8000-000000000020')<>'pending'
 THEN RAISE EXCEPTION 'Rejected client-style mutation still changed a row'; END IF;
END $trigger_compat$;
\echo 'PASS: Exact TEST entity and endpoint triggers reject simulated authenticated verification writes.'

-- A distinct third operator is needed for independent revocation.
INSERT INTO bl_directory_lab.publisher_operators(
 user_id,provisioned_by,active
) VALUES (
 '33333333-3333-4333-8333-333333333333',
 '44444444-4444-4444-8444-444444444444',true
);

-- Real app roles cannot call private invoker functions.
SET ROLE authenticated;
SET request.jwt.claim.sub='44444444-4444-4444-8444-444444444444';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'App could issue Verified badge'; END IF;
 blocked:=false;
 BEGIN PERFORM bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '33333333-3333-4333-8333-333333333333',
  'Evidence has been revoked');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'App could revoke Verified badge'; END IF;
 blocked:=false;
 BEGIN PERFORM 1 FROM bl_directory_lab.issued_badges;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'App read private issued-badge ledger'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: App role cannot invoke service-only issue/revoke or read issued badge ledger.'

-- No prepared request => badge can't be issued even by trusted DB executor.
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000020',
   '44444444-4444-4444-8444-444444444444',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Unprepared request issued'; END IF;
END $deny$;
\echo 'PASS: Service executor alone cannot issue without prior independent review.'

-- Simulate completed separate reviewer/evidence verification in this lab.
-- No actual registry/doc API is invoked; test values are placeholders.
INSERT INTO bl_directory_lab.review_decisions(
 request_id,reviewer_user_id,decision,evidence_sha256
) VALUES
('40000000-0000-4000-8000-000000000020',
 '88888888-8888-4888-8888-888888888888','approve',repeat('a',64)),
('40000000-0000-4000-8000-000000000020',
 '99999999-9999-4999-8999-999999999999','approve',repeat('a',64));

INSERT INTO bl_directory_lab.authority_attestations(
 request_id,attested_by,evidence_sha256,source_kind,
 source_reference_sha256,expires_at
) VALUES (
 '40000000-0000-4000-8000-000000000020',
 '22222222-2222-4222-8222-222222222222',
 repeat('a',64),'government_registry',repeat('1',64),
 clock_timestamp()+interval '60 days'
);
INSERT INTO bl_directory_lab.prepared_publications(
 request_id,entity_id,evidence_sha256,prepared_by
) VALUES (
 '40000000-0000-4000-8000-000000000020',
 '10000000-0000-4000-8000-000000000020',
 repeat('a',64),'66666666-6666-4666-8666-666666666666'
);

DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000020',
   '66666666-6666-4666-8666-666666666666',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Preparing publisher issued their own badge'; END IF;
 blocked:=false;
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000020',
   '88888888-8888-4888-8888-888888888888',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Reviewer issued badge'; END IF;
 blocked:=false;
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000020',
   '11111111-1111-4111-8111-111111111111',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Entity requester issued badge'; END IF;
END $bad$;
\echo 'PASS: Preparer, reviewers and entity requester cannot issue final badge.'

-- No badge longer than authority evidence expiry or maximum 90-day cap.
DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '80 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Badge outlasted attestation'; END IF;
 blocked:=false;
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '100 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Unbounded badge lifespan allowed'; END IF;
END $bad$;
\echo 'PASS: Badge expiration cannot exceed authority expiry or 90-day bound.'

-- A changed authority hash after reviews/preparation must fail closed.
UPDATE bl_directory_lab.authority_attestations
 SET evidence_sha256=repeat('b',64)
 WHERE request_id='40000000-0000-4000-8000-000000000020';
DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Changed authority evidence published'; END IF;
END $bad$;
UPDATE bl_directory_lab.authority_attestations
 SET evidence_sha256=repeat('a',64)
 WHERE request_id='40000000-0000-4000-8000-000000000020';
\echo 'PASS: Issuance revalidates unchanged authority evidence digest.'

-- A deliberately failing event INSERT must revert entity, request and
-- private badge issuance atomically in the same transaction.
CREATE FUNCTION bl_directory_lab.inject_issue_failure()
RETURNS trigger LANGUAGE plpgsql AS $fail$
BEGIN
 IF NEW.action='entity_verified'
 AND NEW.request_id='40000000-0000-4000-8000-000000000020'::uuid
 THEN RAISE EXCEPTION 'FORCED_BADGE_EVENT_FAILURE'; END IF;
 RETURN NEW;
END $fail$;
CREATE TRIGGER inject_issue_event_failure
 BEFORE INSERT ON bl_directory_lab.badge_events
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.inject_issue_failure();
DO $bad$
DECLARE failed boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000020',
   '44444444-4444-4444-8444-444444444444',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN others THEN
  IF SQLERRM LIKE '%FORCED_BADGE_EVENT_FAILURE%' THEN failed:=true;ELSE RAISE;END IF;
 END;
 IF NOT failed THEN RAISE EXCEPTION 'Forced audit failure did not abort issuance'; END IF;
END $bad$;
DROP TRIGGER inject_issue_event_failure ON bl_directory_lab.badge_events;
DROP FUNCTION bl_directory_lab.inject_issue_failure();
DO $check$
BEGIN
 IF EXISTS (SELECT 1 FROM bl_directory_lab.issued_badges
  WHERE request_id='40000000-0000-4000-8000-000000000020')
 OR (SELECT verification_status FROM public.entity_profiles
  WHERE id='10000000-0000-4000-8000-000000000020') <> 'pending'
 OR (SELECT status FROM public.entity_verification_requests
  WHERE id='40000000-0000-4000-8000-000000000020') <> 'pending'
 THEN RAISE EXCEPTION 'Partial badge issued on forced event failure'; END IF;
END $check$;
\echo 'PASS: Audit event failure atomically rolls back badge/entity/request writes.'

DO $issue$
DECLARE result text;
BEGIN
 result:=bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '30 days');
 IF result<>'entity_verified_endpoint_status_unchanged' THEN
   RAISE EXCEPTION 'Wrong trusted entity issuance result'; END IF;
END $issue$;

DO $check$
BEGIN
 IF (SELECT verification_status FROM public.entity_profiles
     WHERE id='10000000-0000-4000-8000-000000000020') <> 'verified'
 OR (SELECT status FROM public.entity_verification_requests
     WHERE id='40000000-0000-4000-8000-000000000020') <> 'approved'
 OR (SELECT state FROM bl_directory_lab.issued_badges
     WHERE entity_id='10000000-0000-4000-8000-000000000020') <> 'verified'
 OR (SELECT verification_status FROM public.entity_endpoints
     WHERE id='20000000-0000-4000-8000-000000000020') <> 'pending'
 OR (SELECT count(*) FROM bl_directory_lab.badge_events
     WHERE entity_id='10000000-0000-4000-8000-000000000020') <> 1
 THEN RAISE EXCEPTION 'Trusted issuance did not update correct independent statuses'; END IF;
END $check$;
\echo 'PASS: Trusted lab issuance verifies ENTITY ONLY, leaves phone pending; audit persisted.'

-- Reissue is prohibited. Even independently valid new request for same
-- official registry reference cannot silently re-claim same identity.
DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Duplicate same request issued'; END IF;
END $bad$;
\echo 'PASS: Same request cannot issue multiple badges.'

INSERT INTO public.entity_profiles(
  id,entity_type,legal_name,verification_status,created_by,country_code
) VALUES (
 '10000000-0000-4000-8000-000000000021','business',
 'Competing Synthetic Registry Entity','pending',
 '11111111-1111-4111-8111-111111111111','IN'
);
INSERT INTO public.entity_verification_requests(
  id,entity_id,requester_user_id,evidence_type,status
) VALUES (
 '40000000-0000-4000-8000-000000000021',
 '10000000-0000-4000-8000-000000000021',
 '11111111-1111-4111-8111-111111111111','gstin','pending'
);
INSERT INTO bl_directory_lab.review_decisions(
 request_id,reviewer_user_id,decision,evidence_sha256
) VALUES
('40000000-0000-4000-8000-000000000021',
 '88888888-8888-4888-8888-888888888888','approve',repeat('a',64)),
('40000000-0000-4000-8000-000000000021',
 '99999999-9999-4999-8999-999999999999','approve',repeat('a',64));
INSERT INTO bl_directory_lab.authority_attestations(
 request_id,attested_by,evidence_sha256,source_kind,
 source_reference_sha256,expires_at
) VALUES (
 '40000000-0000-4000-8000-000000000021',
 '22222222-2222-4222-8222-222222222222',
 repeat('a',64),'government_registry',repeat('1',64),
 clock_timestamp()+interval '60 days'
);
INSERT INTO bl_directory_lab.prepared_publications(
 request_id,entity_id,evidence_sha256,prepared_by
) VALUES (
 '40000000-0000-4000-8000-000000000021',
 '10000000-0000-4000-8000-000000000021',
 repeat('a',64),'66666666-6666-4666-8666-666666666666'
);
DO $duplicate$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
   '40000000-0000-4000-8000-000000000021',
   '44444444-4444-4444-8444-444444444444',
   clock_timestamp()+interval '30 days');
 EXCEPTION WHEN unique_violation THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Duplicate official registry identity claimed'; END IF;
 IF (SELECT verification_status FROM public.entity_profiles
    WHERE id='10000000-0000-4000-8000-000000000021')<>'pending' THEN
  RAISE EXCEPTION 'Failed competing claim changed entity status'; END IF;
END $duplicate$;
\echo 'PASS: Same authoritative source reference cannot be assigned to another entity.'

-- Synthetic proof of previously independently verified endpoint, and
-- another suspended endpoint. This seeding is NOT a real verification.
UPDATE public.entity_endpoints
SET verification_status='verified',verified_at=clock_timestamp()-interval '1 day',
 verification_method='synthetic_lab_only'
WHERE id='20000000-0000-4000-8000-000000000020';
-- The exact TEST cross-claim trigger forbids another entity from claiming
-- the same normalized number while the existing verified claim is active.
DO $duplicate_mobile$
DECLARE refused boolean:=false;
BEGIN
 BEGIN
  INSERT INTO public.entity_endpoints(
   id,entity_id,endpoint_type,endpoint_value,display_value,
   verification_status
  ) VALUES (
   '20000000-0000-4000-8000-000000000029',
   '10000000-0000-4000-8000-000000000021',
   'mobile','+91 90000 00020','+91 90000 00020','pending'
  );
 EXCEPTION WHEN others THEN
  IF SQLERRM='Endpoint already verified or reserved for another organisation'
  THEN refused:=true; ELSE RAISE; END IF;
 END;
 IF NOT refused OR EXISTS(
  SELECT 1 FROM public.entity_endpoints
  WHERE id='20000000-0000-4000-8000-000000000029'
 ) THEN RAISE EXCEPTION 'Real TEST cross-entity number conflict not blocked'; END IF;
END $duplicate_mobile$;
\echo 'PASS: Exact TEST cross-entity trigger blocks competing normalized verified phone claim.'

INSERT INTO public.entity_endpoints(
 id,entity_id,endpoint_type,endpoint_value,display_value,
 verification_status,verified_at
) VALUES(
 '20000000-0000-4000-8000-000000000022',
 '10000000-0000-4000-8000-000000000020',
 'mobile','9000000022','9000000022','suspended',clock_timestamp()-interval '1 day'
);
INSERT INTO public.entity_endpoints(
 id,entity_id,endpoint_type,endpoint_value,display_value,
 verification_status,verified_at
) VALUES(
 '20000000-0000-4000-8000-000000000023',
 '10000000-0000-4000-8000-000000000021',
 'mobile','9000000023','9000000023','verified',clock_timestamp()-interval '1 day'
);
DO $revoke_denied$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  'Issuer may not revoke own issued identity');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Issuer revoked their own approval'; END IF;
 blocked:=false;
 BEGIN PERFORM bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '33333333-3333-4333-8333-333333333333','short');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Short or blank revocation accepted'; END IF;
END $revoke_denied$;
\echo 'PASS: Revocation requires a different trusted operator and meaningful reason.'

-- Deliberately fail audit on entity_revoked to test all-or-nothing safety.
CREATE FUNCTION bl_directory_lab.inject_revoke_failure()
RETURNS trigger LANGUAGE plpgsql AS $fail$
BEGIN
 IF NEW.action='entity_revoked'
 AND NEW.entity_id='10000000-0000-4000-8000-000000000020'::uuid
 THEN RAISE EXCEPTION 'FORCED_REVOKE_EVENT_FAILURE'; END IF;
 RETURN NEW;
END $fail$;
CREATE TRIGGER inject_revoke_event_failure
 BEFORE INSERT ON bl_directory_lab.badge_events
 FOR EACH ROW EXECUTE FUNCTION bl_directory_lab.inject_revoke_failure();
DO $bad$
DECLARE failed boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '33333333-3333-4333-8333-333333333333',
  'Authority withdrew independent verified identity');
 EXCEPTION WHEN others THEN
  IF SQLERRM LIKE '%FORCED_REVOKE_EVENT_FAILURE%' THEN failed:=true;ELSE RAISE;END IF;
 END;
 IF NOT failed THEN RAISE EXCEPTION 'Revoke failure did not abort'; END IF;
END $bad$;
DROP TRIGGER inject_revoke_event_failure ON bl_directory_lab.badge_events;
DROP FUNCTION bl_directory_lab.inject_revoke_failure();
DO $check$
BEGIN
 IF (SELECT verification_status FROM public.entity_profiles
  WHERE id='10000000-0000-4000-8000-000000000020') <> 'verified'
 OR (SELECT state FROM bl_directory_lab.issued_badges
  WHERE entity_id='10000000-0000-4000-8000-000000000020') <> 'verified'
 OR (SELECT verification_status FROM public.entity_endpoints
  WHERE id='20000000-0000-4000-8000-000000000020') <> 'verified'
 OR (SELECT verification_status FROM public.entity_endpoints
  WHERE id='20000000-0000-4000-8000-000000000022') <> 'suspended'
 THEN RAISE EXCEPTION 'Partial revocation after forced event failure'; END IF;
END $check$;
\echo 'PASS: Revoke audit failure atomically restores organization and endpoints.'

DO $revoke$
DECLARE result text;
BEGIN
 result:=bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '33333333-3333-4333-8333-333333333333',
  'Authority withdrew independent verified identity');
 IF result<>'entity_revoked_verified_endpoints_revoked' THEN
  RAISE EXCEPTION 'Revocation returned wrong state'; END IF;
END $revoke$;
DO $check$
BEGIN
 IF (SELECT verification_status FROM public.entity_profiles
   WHERE id='10000000-0000-4000-8000-000000000020') <> 'revoked'
 OR (SELECT state FROM bl_directory_lab.issued_badges
   WHERE entity_id='10000000-0000-4000-8000-000000000020') <> 'revoked'
 OR (SELECT verification_status FROM public.entity_endpoints
   WHERE id='20000000-0000-4000-8000-000000000020') <> 'revoked'
 OR (SELECT verification_status FROM public.entity_endpoints
   WHERE id='20000000-0000-4000-8000-000000000022') <> 'revoked'
 OR (SELECT revoked_by FROM public.entity_endpoints
   WHERE id='20000000-0000-4000-8000-000000000020')
   IS DISTINCT FROM '33333333-3333-4333-8333-333333333333'::uuid
 OR (SELECT revoked_by FROM public.entity_endpoints
   WHERE id='20000000-0000-4000-8000-000000000022')
   IS DISTINCT FROM '33333333-3333-4333-8333-333333333333'::uuid
 OR (SELECT verification_status FROM public.entity_endpoints
   WHERE id='20000000-0000-4000-8000-000000000023') <> 'verified'
 OR (SELECT count(*) FROM bl_directory_lab.badge_events
    WHERE entity_id='10000000-0000-4000-8000-000000000020') <> 4
 THEN RAISE EXCEPTION 'Revocation did not atomically cascade status or audit'; END IF;
END $check$;
\echo 'PASS: Independent revoker invalidates entity and its previously verified/suspended endpoints only.'

DO $bad$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM bl_directory_lab.revoke_verified_entity_lab_v1(
  '10000000-0000-4000-8000-000000000020',
  '33333333-3333-4333-8333-333333333333',
  'Repeated unauthorized revocation action');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Revoked badge allowed second revocation'; END IF;
 blocked:=false;
 BEGIN PERFORM bl_directory_lab.issue_verified_entity_lab_v1(
  '40000000-0000-4000-8000-000000000020',
  '44444444-4444-4444-8444-444444444444',
  clock_timestamp()+interval '30 days');
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Revoked badge silently reissued'; END IF;
END $bad$;
\echo 'PASS: Revoked badge cannot be silently reissued or revoked twice.'

DO $immutable$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  UPDATE bl_directory_lab.badge_events SET action='entity_verified'
  WHERE entity_id='10000000-0000-4000-8000-000000000020';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Badge issuance/revocation audit mutable'; END IF;
 blocked:=false;
 BEGIN
  DELETE FROM bl_directory_lab.badge_events
  WHERE entity_id='10000000-0000-4000-8000-000000000020';
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Badge audit deletable'; END IF;
END $immutable$;
\echo 'PASS: Issued/revoked badge event ledger remains append-only.'

DO $last$
BEGIN
 IF has_function_privilege('authenticated',
  'bl_directory_lab.issue_verified_entity_lab_v1(uuid,uuid,timestamptz)',
  'EXECUTE')
 OR has_function_privilege('authenticated',
  'bl_directory_lab.revoke_verified_entity_lab_v1(uuid,uuid,text)',
  'EXECUTE')
 OR has_schema_privilege('authenticated','bl_directory_lab','USAGE')
 THEN RAISE EXCEPTION 'Client has private publication privileges'; END IF;
END $last$;
\echo 'PASS: No client grants on trusted service functions or private schema.'
