\set ON_ERROR_STOP on
\echo 'VERIFIED DIRECTORY PG16 / SYNTHETIC ENTITY TESTS ONLY'

INSERT INTO public.entity_profiles
 (id,entity_type,legal_name,display_name,jurisdiction,
  verification_status,verification_method,verified_at,
  verification_expires_at)
VALUES
 ('10000000-0000-4000-8000-000000000001','police','Rourkela Example Police','Example Police','Rourkela, Odisha',
  'verified','government_authority',now()-interval '30 days',now()+interval '100 days'),
 ('10000000-0000-4000-8000-000000000002','business','Pending Example Ltd','Pending Example',NULL,
  'pending',NULL,NULL,NULL),
 ('10000000-0000-4000-8000-000000000003','business','Verified Name Pending Number Ltd','Pending Number',NULL,
  'verified','business_registry',now()-interval '2 days',NULL),
 ('10000000-0000-4000-8000-000000000004','business','Expired Entity Ltd','Expired Entity',NULL,
  'verified','business_registry',now()-interval '200 days',now()-interval '1 second'),
 ('10000000-0000-4000-8000-000000000005','business','Expired Number Ltd','Expired Number',NULL,
  'verified','business_registry',now()-interval '5 days',NULL),
 ('10000000-0000-4000-8000-000000000006','business','Revoked Number Ltd','Revoked Number',NULL,
  'verified','business_registry',now()-interval '5 days',NULL),
 ('10000000-0000-4000-8000-000000000007','business','Inactive Role Ltd','Inactive Role',NULL,
  'verified','business_registry',now()-interval '5 days',NULL),
 ('10000000-0000-4000-8000-000000000008','business','Independent Match Ltd','Independent Match',NULL,
  'verified','business_registry',now()-interval '5 days',NULL),
 ('10000000-0000-4000-8000-000000000009','hospital','Unsigned Verification Ltd','Unsigned Verification',NULL,
  'verified','hospital_authority',NULL,NULL),
 ('10000000-0000-4000-8000-000000000010','business','Competing Claim Ltd','Competing Claim',NULL,
  'pending',NULL,NULL,NULL);

INSERT INTO public.entity_endpoints
 (id,entity_id,endpoint_type,endpoint_value,display_value,verification_status,
  verified_at,verification_expires_at,revoked_at)
VALUES
 ('20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001',
  'mobile','9876543210','+91 98765 43210','verified',now()-interval '30 days',now()+interval '1 year',NULL),
 ('20000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000002',
  'mobile','9876543210','+91 98765 43210','verified',now()-interval '20 days',NULL,NULL),
 ('20000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000003',
  'mobile','9765432109','9765432109','pending',NULL,NULL,NULL),
 ('20000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000004',
  'mobile','9654321098','9654321098','verified',now()-interval '200 days',NULL,NULL),
 ('20000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000005',
  'mobile','9543210987','9543210987','verified',now()-interval '60 days',
  now()-interval '1 second',NULL),
 ('20000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000006',
  'mobile','9432109876','9432109876','verified',now()-interval '60 days',NULL,now()-interval '1 day'),
 ('20000000-0000-4000-8000-000000000007','10000000-0000-4000-8000-000000000007',
  'mobile','9321098765','9321098765','verified',now()-interval '10 days',NULL,NULL),
 ('20000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000008',
  'mobile','9210987654','9210987654','verified',now()-interval '10 days',NULL,NULL),
 ('20000000-0000-4000-8000-000000000009','10000000-0000-4000-8000-000000000010',
  'mobile','9876543210','9876543210','verified',now()-interval '5 days',NULL,NULL);

INSERT INTO public.entity_contact_points(id,entity_id,active)
VALUES
 ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000007',false),
 ('30000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000008',true);
INSERT INTO public.entity_contact_point_endpoints(contact_point_id,endpoint_id)
VALUES
 ('30000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000007'),
 ('30000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000008');

-- Without explicit release, no auth/anon execute and no Data API table read.
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory('Rourkela',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Directory search callable before release'; END IF;
 blocked:=false;
 BEGIN
  PERFORM * FROM public.entity_profiles;
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Direct entity profiles SELECT allowed'; END IF;
END $deny$;
RESET ROLE;
SET ROLE anon;
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  PERFORM public.search_verified_directory('Rourkela',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Anonymous search allowed'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: RPC disabled for all clients; no raw directory table access.'

-- Temporarily grant test role ONLY in this disposable database.
GRANT EXECUTE ON FUNCTION public.search_verified_directory(text,integer) TO authenticated;
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $exact$
DECLARE r record; countrows integer;
BEGIN
 SELECT * INTO r FROM public.search_verified_directory('+91 98765 43210',25);
 IF NOT FOUND OR r.entity_id <> '10000000-0000-4000-8000-000000000001'::uuid
  OR r.match_type <> 'exact_endpoint' OR r.matched_endpoint_type <> 'mobile'
  OR r.matched_endpoint_display_value <> '+91 98765 43210'
  OR r.verification_status <> 'verified'
 THEN RAISE EXCEPTION 'Exact mobile did not resolve verified owner'; END IF;
 SELECT COUNT(*) INTO countrows FROM public.search_verified_directory('9876543210',25);
 IF countrows<>1 THEN RAISE EXCEPTION 'National phone format mismatch'; END IF;
 SELECT COUNT(*) INTO countrows FROM public.search_verified_directory('76543210',25);
 IF countrows<>0 THEN RAISE EXCEPTION 'Last-8-digits exposed private identity'; END IF;
 SELECT COUNT(*) INTO countrows FROM public.search_verified_directory('98765',25);
 IF countrows<>0 THEN RAISE EXCEPTION 'Prefix phone lookup exposed identity'; END IF;
 SELECT COUNT(*) INTO countrows FROM public.search_verified_directory('919876543210',25);
 IF countrows<>1 THEN RAISE EXCEPTION '91 phone normalization mismatch'; END IF;
END $exact$;
\echo 'PASS: Only full verified mobile matches, including +91; partial phones leak nothing.'

DO $negative$
DECLARE counts int;
BEGIN
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9765432109',25);
 IF counts<>0 THEN RAISE EXCEPTION 'Pending endpoint treated as verified'; END IF;
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9654321098',25);
 IF counts<>0 THEN RAISE EXCEPTION 'Expired verified entity returned'; END IF;
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9543210987',25);
 IF counts<>0 THEN RAISE EXCEPTION 'Expired verified endpoint returned'; END IF;
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9432109876',25);
 IF counts<>0 THEN RAISE EXCEPTION 'Revoked endpoint returned'; END IF;
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9321098765',25);
 IF counts<>0 THEN RAISE EXCEPTION 'Archived contact role still exposed'; END IF;
 SELECT COUNT(*) INTO counts FROM public.search_verified_directory('9210987654',25);
 IF counts<>1 THEN RAISE EXCEPTION 'Active verified contact role excluded'; END IF;
END $negative$;
\echo 'PASS: Pending, revoked, expired and archived-role endpoints excluded.'

DO $names$
DECLARE r record; found_count int;
BEGIN
 SELECT * INTO r FROM public.search_verified_directory('Rourkela',25);
 IF NOT FOUND OR r.entity_id <> '10000000-0000-4000-8000-000000000001'::uuid
   OR r.match_type <> 'entity_name'
   OR r.matched_endpoint_type IS NOT NULL
   OR r.matched_endpoint_display_value IS NOT NULL
 THEN RAISE EXCEPTION 'Name search leaked endpoint or missed verified entity'; END IF;
 SELECT COUNT(*) INTO found_count FROM public.search_verified_directory('Pending Example',25);
 IF found_count<>0 THEN RAISE EXCEPTION 'Pending entity found by name'; END IF;
 SELECT COUNT(*) INTO found_count FROM public.search_verified_directory('Expired Entity',25);
 IF found_count<>0 THEN RAISE EXCEPTION 'Expired entity found by name'; END IF;
 SELECT COUNT(*) INTO found_count FROM public.search_verified_directory('Unsigned Verification',25);
 IF found_count<>0 THEN RAISE EXCEPTION 'Never-verified entity returned'; END IF;
 SELECT COUNT(*) INTO found_count FROM public.search_verified_directory('example police',25);
 IF found_count<>1 THEN RAISE EXCEPTION 'Case-insensitive verified name search broken'; END IF;
 SELECT COUNT(*) INTO found_count FROM public.search_verified_directory('%%',25);
 IF found_count<>0 THEN RAISE EXCEPTION 'SQL wildcard input broadened directory search'; END IF;
END $names$;
\echo 'PASS: Verified name/location search is key/endpoint-free, case-insensitive, wildcard safe.'

DO $bad$
DECLARE denied boolean:=false;
BEGIN
 BEGIN PERFORM public.search_verified_directory('Rourkela',0);
 EXCEPTION WHEN invalid_parameter_value THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Invalid zero limit accepted'; END IF;
 denied:=false;
 BEGIN PERFORM public.search_verified_directory('Rourkela',26);
 EXCEPTION WHEN invalid_parameter_value THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Unbounded limit accepted'; END IF;
 denied:=false;
 BEGIN PERFORM public.search_verified_directory('Rourkela',NULL);
 EXCEPTION WHEN invalid_parameter_value THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Null limit accepted'; END IF;
 denied:=false;
 BEGIN PERFORM public.search_verified_directory('a',25);
 EXCEPTION WHEN invalid_parameter_value THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION '1-character query accepted'; END IF;
 denied:=false;
 BEGIN PERFORM public.search_verified_directory(repeat('a',121),25);
 EXCEPTION WHEN invalid_parameter_value THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'Oversized query accepted'; END IF;
END $bad$;
\echo 'PASS: Invalid query/limit inputs rejected before scanning entities.'
RESET ROLE;

SET ROLE authenticated;
RESET request.jwt.claim.sub;
DO $deny$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.search_verified_directory('Rourkela',25);
 EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'No auth.uid() admitted to search'; END IF;
END $deny$;
RESET ROLE;
\echo 'PASS: No account identity means directory search denied.'

-- Country scoping: a foreign entity claiming the same ten digits must
-- NOT make the India-specific mobile lookup ambiguous or look verified.
INSERT INTO public.entity_profiles(
 id,entity_type,legal_name,display_name,country_code,
 verification_status,verification_method,verified_at
) VALUES (
 '10000000-0000-4000-8000-000000000011','business','Foreign Example Claim',
 'Foreign Claim','US','verified','foreign_registry',now()-interval '2 days'
);
INSERT INTO public.entity_endpoints(
 id,entity_id,endpoint_type,endpoint_value,display_value,
 verification_status,verified_at
) VALUES (
 '20000000-0000-4000-8000-000000000011',
 '10000000-0000-4000-8000-000000000011',
 'mobile','9876543210','9876543210',
 'verified',now()-interval '1 day'
);
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $country$
DECLARE r record;
BEGIN
 SELECT * INTO r FROM public.search_verified_directory('9876543210',25);
 IF r.entity_id IS DISTINCT FROM '10000000-0000-4000-8000-000000000001'::uuid THEN
   RAISE EXCEPTION 'Foreign mobile claim confused Indian directory';
 END IF;
END $country$;
RESET ROLE;
\echo 'PASS: India mobile lookup cannot inherit foreign-country endpoint claim.'

-- A duplicate verified claim from a different entity must not falsely
-- affirm two owners for one number, despite each endpoint being verified.
UPDATE public.entity_profiles SET verification_status='verified',
 verified_at=now()-interval '1 day',verification_method='business_registry'
WHERE id='10000000-0000-4000-8000-000000000010';
SET ROLE authenticated;
SET request.jwt.claim.sub='11111111-1111-4111-8111-111111111111';
DO $ambiguous$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN PERFORM public.search_verified_directory('9876543210',25);
 EXCEPTION WHEN SQLSTATE 'P0001' THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'Conflicting entity ownership silently trusted'; END IF;
END $ambiguous$;
RESET ROLE;
\echo 'PASS: Conflicting verified number claims raise manual-review error, no false badge.'

-- Default-deny after the test run, preserving no release permissions.
REVOKE EXECUTE ON FUNCTION public.search_verified_directory(text,integer)
 FROM authenticated;
DO $check$
BEGIN
 IF has_function_privilege('authenticated',
  'public.search_verified_directory(text,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'Candidate left callable after lab tests'; END IF;
END $check$;
\echo 'PASS: New directory RPC EXECUTE denied after all isolated tests.'
