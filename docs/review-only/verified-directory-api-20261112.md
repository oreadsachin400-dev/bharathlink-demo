# BharathLink Verified Directory — read-only reconciliation and candidate API
**12 Nov 2026 | SECURITY HOLD | REVIEW ONLY | NO TEST/PROD DEPLOY**

## Original source / backend findings

- GitHub main index.html calls search_verified_directory(p_query text,
  p_limit integer) and falls back to search_verified_entities on missing
  function, but **both are absent** from official TEST public RPC inventory.
- The actual official TEST project fsdusofbpwdrdvgexxyw DOES contain
  entity_profiles, entity_endpoints, entity_contact_points,
  entity_contact_point_endpoints and the helper
  normalize_entity_endpoint(p_type text, p_value text).
- Data aggregate inspected read-only on 12 Nov: 0 entity_profiles,
  0 active verified entities and 0 active verified endpoints, including
  0 verified mobile endpoints. No person/organisation details were read.
  Therefore this candidate cannot provide meaningful live results without
  an independently authorized onboarding and verification process.
- Raw authenticated/anon SELECT/INSERT/UPDATE permissions for the three
  entity tables checked are false. Any public RPC must remain narrowly
  restricted and must NOT expose pending or revoked entities.
- Current number normalization strips non-digits and +91 for 12 digits.
  This candidate enforces **complete Indian mobile numbers**, not prefixes,
  last digits, or substring matching.

## Candidate search_verified_directory(p_query, p_limit)

Code: sql/review-only/search_verified_directory_candidate.sql

- Returns verified, current, non-revoked, nonexpired records only.
  Entity verification and endpoint verification are independent.
- An exact Indian mobile returns match_type=exact_endpoint with the
  matching verified public endpoint display value. Non-Indian country
  records with the same last 10 digits cannot satisfy that lookup.
- A verified organization/department name or location search returns
  match_type=entity_name with **NULL endpoint match data**.
- User-submitted SQL wildcard symbols are escaped; bounded query length
  2..120 and p_limit 1..25; requires auth.uid().
- If two *distinct verified IN entities* claim the same normalized mobile,
  a manual-review exception is raised; the UI must say it cannot verify
  the ownership, never select one arbitrarily.
- Contact endpoints linked to a contact point with all inactive roles
  are withheld; unlinked, independently verified entity endpoints may
  still be returned. This behavior requires product review.
- CREATE+REVOKE wrapped in one transaction, explicit search_path='';
  EXECUTE revoked from PUBLIC, anon, authenticated, service_role.
  No new functions were executed or installed on official TEST/PROD.

## Disposable PostgreSQL 16 results

[CI #43091263039](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43091263039)
**SUCCESS — 9/9 security test groups** with synthetic organizations,
contacts, phone numbers and official TEST normalizer definition:
- default RPC EXECUTE and direct table SELECT denied
- only exact verified full mobile (+91/national) matches; partial denied
- pending, revoked, expired and inactive contact-point results excluded
- verified name/location search and wildcard escaping
- bounded input and authentication checks
- Indian number not confused by same digits of foreign-country entity
- duplicate verified in-country number claims raise explicit conflict
- authenticated EXECUTE revoked again after isolated test

## Release blockers / no-go

1. **NO live verified entities:** establish authoritative vetting,
   approval, verification revocation, expiration, evidence audit and
   publishing consent. Do not insert fabricated verified organizations.
2. **No abuse throttling yet:** exact-phone lookup across many searches
   can become a phone-number enumeration tool. A verified identity
   infrastructure MUST implement authenticated per-account/device/IP
   rate limits, detection and alerting before enabling EXECUTE.
3. **No direct proof of signer or actual customer identity:** a verified
   organization/endpoint is not a guarantee that a caller is safe, and
   no match does NOT mean fake, unregistered or criminal.
4. **No phone-landline coverage:** currently only Indian 10-digit mobile
   endpoint_type; official police/utility landlines, extensions and
   international numbers need separate model + normalization review.
5. **Other directory APIs missing:** search_verified_entities,
   get_verified_entity_by_endpoint, list_verified_entity_endpoints,
   list_verified_entity_contact_points, onboarding and management
   RPCs still require compatible implementations and testing.
6. **Live Netlify frontend remains DEMO-backed** in GitHub main, and
   separately published TEST source differs. Do not blind-swap URLs.
7. **Existing RLS, lifecycle and cross-entity ownership triggers**
   must be reviewed end-to-end on an independent staging project with
   a real authorized verifier. This disposable fixture models only
   critical tables, not the full real identity verification pipeline.
8. Do not enable public search, deploy TEST or PROD, or represent this
   as functioning Verified Directory until approval and Android UI tests.

This PR adds source/tests/documentation only to a separate draft branch.
It contains no live user data, tokens, actual private numbers, or secrets.
