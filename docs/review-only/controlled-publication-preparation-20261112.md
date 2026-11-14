# BharathLink — Trusted evidence and controlled publication preparation

**12 Nov 2026 | DRAFT SECURITY REVIEW | NO LIVE TEST/PROD CHANGES**

## Verified disposable tests

[Isolated PG16 CI #43169012264](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43169012264) **SUCCESS**.

Test inventory: 9 directory lookup checks, 11 independent-review checks,
9 publication-preparation and revocation checks, 6 quota checks,
and one observed two-connection PostgreSQL quota-lock race.
Total: **35 named PASS groups + 1 concurrency PASS**.

New review-only files:
- `sql/review-only/entity_publication_preparation_lab.sql`
- `tests/entity_publication_preparation_contract.pgsql`

These use fabricated reviewer accounts, business entities, evidence hashes,
authority sources and session IDs. There are no real verifier credentials,
documents or government-registry checks.

## Private preparation sequence (not publication)

1. The organization is still pending. Its requester and authorized owner
   cannot review or prepare publication.
2. Two separately provisioned, currently active reviewers must have
   approved exactly the same evidence digest, with no negative or conflicting
   review entries. Each reviewer contributes at most one decision.
3. A third independent attester must have deposited an unexpired authority
   attestation referencing that same digest and an authority-source hash.
   This evidence record is **test-inserted**; no real source verification,
   signature validation or evidence custody has been implemented.
4. A fourth actor (active, separately provisioned publisher) must not be
   the requester, creator, entity member, reviewer or attester.
5. The candidate creates only a private prepared-publication row and an
   append-only audit event. It deliberately DOES NOT update
   entity_profiles.verification_status, entity_endpoints or the request.
6. Another active independent publisher may revoke the preparation with
   a reason. A revoked request cannot be restored under the same ID.
   The revocation is private-only; it is NOT real badge revocation.

All new public-named RPC signatures have CREATE+REVOKE in one transaction.
No EXECUTE grant is left for PUBLIC, anon, authenticated or service_role.
Lab-only temporary grants were revoked after tests.

## Real-world trust boundary and required next work

A SQL SHA-256 digest cannot authenticate an official document or ownership
of a phone number. Two distinct user UUIDs do not prove two distinct humans.
An operator registry populated by a trusted administrator must itself be
backed by auditable organizational authority, verified identities,
out-of-band signer approval, separation of duties, revocation, and
periodic review.

For real publication, build a separate trusted backoffice service that
verifies evidence with authoritative sources (e.g. registered authority,
regulator, business registry, delegated organization) and records source,
timestamp, operator, expiry and legal basis without exposing personal
documents in app logs. Review the actual existing
protect_entity_verification_fields and
protect_entity_endpoint_verification_fields triggers when selecting
a service authentication model. Do not bypass them from a public RPC.

A future publication transaction must preserve entity and endpoint
verification independence, apply cross-entity endpoint conflicts,
be replay-safe, record append-only audit events and support immediate
revocation at every read route. Backoffice roles, client JWT/session
checks and trusted service keys must be independently reviewed.

The trial account quota (5/minute, 50/day) is NOT sufficient against
multi-account, distributed-IP/device enumeration or every alternate
directory endpoint. Edge/API gateway abuse prevention and retention
policies remain release blockers.

Other blockers: 0 authorized live entity requests and verified entities
at last read-only check; missing official TEST directory RPCs; GitHub
frontend bound to old DEMO rather than official TEST; unverified Android
signer-enrollment and no two-phone acceptance.

**SECURITY HOLD: no public Verified badge, no live SQL deployment, no RPC
EXECUTE permissions, no Netlify build, no APK installation, no key reset.**
