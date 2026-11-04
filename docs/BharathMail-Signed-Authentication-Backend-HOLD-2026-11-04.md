# BharathLink Mail — Independent SPF/DKIM/DMARC Verifier Report Gateway (STAGED)

**4 November 2026 | GitHub source + disposable PostgreSQL 17 CI | RELEASE HOLD**

## Verified result

- Branch: `bharathlink-mail-signed-auth-backend-hold-ci`
- [Latest 3-job CI run #41817413735](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41817413735) — **SUCCESS, 3/3 jobs**.
- **139/139 Node.js test cases PASS:** 15 P-256 signed-auth unit/Edge tests + 9 integrated P-256 Edge ↔ real disposable PostgreSQL tests + 24 preexisting Mail Trust UI tests + 91 earlier security regression tests. PostgreSQL source/permission/owner/RLS/nonce and immutability assertions also PASS.
- No live Supabase SQL or Edge deployment, no Resend setup change, no Netlify deploy, no Android APK build, no signing/identity/trust grants. **The committed verifier entrypoint is explicitly hard-disabled** (`MAIL_AUTH_RELEASED=false`).

## What was implemented

1. `supabase/functions/bl-mail-auth-attest/signed-report.mjs` implements strict field validation and real cryptographic **P-256 ECDSA / SHA-256 signature verification** of a claimed independent SMTP/DNS verifier report. It binds the exact provider message ID, sender, recipient, sender domain, SPF/DKIM/DMARC results, verifier key ID, nonce and short issuance/expiry window. Unknown fields, unsigned or tampered data, invalid/ambiguous/multiline sender addresses, expired reports and domain misalignment are rejected.
2. `supabase/functions/bl-mail-auth-attest/index.ts` is a **not-deployed, hard-disabled** Edge Function source. Even an environment variable or an HTTP request cannot turn the gate on. An isolated test copy toggles the boolean to exercise the same code path; source remains OFF. The enabled synthetic copy validates a P-256 verifier signature **before** invoking its service-only database commit.
3. `sql/staged/TEST-bharatmail-signed-sender-auth-v1.sql` stages an append-only `public.bharatmail_sender_auth_v1` receipt table with owner-only authenticated SELECT using RLS, no anon access, no authenticated inserts, a service-only **SECURITY INVOKER** RPC, immutable evidence rows, unique report nonce and exactly one receipt per provider email ID. Atomic SQL checks require a processed inbound event and a matching routed external message, From address and reply-token recipient. Existing TEST database is untouched.
4. `tests/fixtures/mail-auth-schema.sql` and `tests/fixtures/mail-auth-rpc-assertions.sql` run on PostgreSQL **17** in GitHub Actions only, testing denied direct callers, user isolation, recipient swapping, previously failed inbound mail, pending routing, conflicting digests, nonce replay and attempts to alter receipts.
5. `tests/mail-auth-signed-gate.test.mjs` runs real P-256 positive/negative signatures, key substitution, header spoof, exact SPF/DKIM alignment with claimed From domain, expiry, malformed address, disabled gateway and synthetic HTTP/DB contracts.
6. `tests/mail-auth-edge-postgres-integrated.test.mjs` runs P-256 signature validation through a synthetic enabled copy of the Edge handler and **actual ephemeral PostgreSQL RPCs**, verifying atomic one-owner receipt, duplicate-only idempotence, mismatched sender/recipient rejection, second-account isolation, conflicting report and signed nonce replay rejection.
7. `.github/workflows/bharatmail-signed-auth-staged-ci.yml` is source-only, GitHub Actions v5 + Ubuntu 24.04 with no package, APK, signing, deployment, webhook registration or secret mutation.

## Security trust boundaries (critical)

**What a valid report proves:** An assertion was signed by the holder of the corresponding private P-256 verifier key, and its fields are bound to one recorded routed email by server-side SQL. The signed report can carry independently computed SPF/DKIM/DMARC results.

**What it does not yet prove:** That the verifier is a real, audited receiving SMTP/DNS authority or that it actually performed the SPF/DKIM/DMARC calculations correctly. **No real verifier authority has been connected or approved.** No report in CI is a real production message or genuine sender-authentication evidence. Signatures use generated synthetic keys. The system does **not** compute SPF, DKIM or DMARC directly from incoming mail in this phase.

The existing live Resend `email.received` Svix-signed webhook confirms webhook origin, **not** email sender identity. The Resend Receiving API returns message headers, but sender-included `Authentication-Results` is not automatically trusted. Actual SPF requires trustworthy connecting SMTP IP and envelope MAIL FROM; DKIM requires the original signed MIME and validated DNS public keys; DMARC requires a verified SPF/DKIM pass aligned with RFC policy. An untrusted email header, domain DNS record existence, sender name, directory match, legal-name claim or successful email delivery does **not** meet those requirements.

For this first contract, a `dmarc=pass` report is accepted only when the separate signed assertion includes at least one `spf=pass` or `dkim=pass` with **exact matching From-domain alignment**. This is deliberately more restrictive than relaxed DMARC alignment and does **not** perform full DMARC policy evaluation or verify actual DNS itself. Do not label the field as a full standards-compliant DMARC verifier.

## Release gates requiring independent evidence

- Independent real receiving SMTP/DNS verifier capable of authenticating the actual connection IP, envelope sender, DKIM canonicalized MIME, TXT DNS/key lookups and DMARC domain alignment (including organizational-domain public-suffix list where applicable); verify performance, failure modes and ARC/forwarding policy. No such vetted service is currently wired up.
- Independently managed issuer P-256 private key in audited custody; pinned public JWK with key ID, rotation and revocation policy; signed source evidence, anti-replay, audit logs, expiration and incident response. **Do not place any issuer private signing key in GitHub, app HTML or Supabase client**.
- Separate security review of database migration, RLS, service-role invocation, identity-to-tenant binding, mail preservation/quarantine behavior, disclosure privacy and evidence retention. `service_role` is highly privileged: the database RPC by itself cannot cryptographically verify the P-256 signature and must never be exposed to untrusted callers.
- Independently test a real Resend inbound mail with authoritative SMTP receipt evidence and inspect false-positive cases before any TEST activation. A VALID signature from a synthetic signer alone cannot justify going live.
- After reviewed backend activation, wire a separate owner-scoped **read-only** client fetch of receipt results to the existing Mail Trust UI; do not let user-controlled mail fields or forged `Authentication-Results` elevate status. **Current frontend still explicitly shows domain auth NOT CHECKED**, and existing Mail Trust heuristics remain warnings only.
- Existing unrelated Play Protect warning, original KeyPrep signing custody, first-device authorization and independent real identity governance remain on HOLD; this Mail work does not change them.

## Source-only verification commands

- Node: `node --test tests/mail-auth-signed-gate.test.mjs`
- Mail UI: `node --test tests/bharatmail-trust-engine.test.mjs`
- Disposable database: run `tests/fixtures/mail-auth-schema.sql`, then `sql/staged/TEST-bharatmail-signed-sender-auth-v1.sql`, then `tests/fixtures/mail-auth-rpc-assertions.sql` against a *fresh ephemeral PostgreSQL 17 database only*.
- Integrated P-256 + real PostgreSQL: `node --test tests/mail-auth-edge-postgres-integrated.test.mjs` with a fresh disposable PostgreSQL fixture.

**Verdict: VERIFIED CODE AND SYNTHETIC CI. NOT A LIVE SPF/DKIM/DMARC AUTHENTICATION SERVICE. No authorization to deploy or mark senders verified.**
