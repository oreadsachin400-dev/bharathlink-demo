# BharathLink Mail — Cloudflare Email Routing Read-only Evidence Candidate (HARD HOLD)

**4 November 2026** | TEST branch `bharathlink-mail-cloudflare-worker-auth-evidence-ci`
**Independent upstream provider alternative to a custom SMTP receiver**

## Decision: pursue an isolated Cloudflare Email Routing / Email Worker pilot

Cloudflare's official documentation currently states that Email Routing prepends an
`Authentication-Results` header with `mx.cloudflare.net` as authserv-id
before invoking an email Worker, and that the first such header is platform
generated. The Worker event provides an SMTP envelope sender (`message.from`),
the envelope recipient (`message.to`), message headers, raw MIME and rawSize.

This supplies a possible **real receiver-owned SPF / DKIM / DMARC observation**
without building or operating a bespoke public SMTP daemon, after an actual
reviewed Cloudflare receiving route is configured and independently tested.
Our existing Resend `email.received` webhook is provider-origin evidence
only; it does not establish the sender's SMTP connecting IP, MAIL FROM and
aligned SPF/DKIM/DMARC results.

Official references:
- https://developers.cloudflare.com/email-service/api/route-emails/email-handler/
- https://developers.cloudflare.com/email-service/platform/pricing/
- https://developers.cloudflare.com/email-service/configuration/subdomains/
- https://developers.cloudflare.com/email-service/configuration/domains/
- https://developers.cloudflare.com/email-service/platform/limits/
- https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html
- https://resend.com/features/inbound

Cloudflare Email Routing can run on Workers Free, with Worker CPU and
request limits. As of 4 Nov 2026, the published pricing page lists unlimited
inbound routing volume, but Workers processing has separate usage limits.
AWS SES is another documented provider-generated SPF/DKIM/DMARC verdict
candidate, but demands a separate SNS/S3 signature + original MIME binding
design. No third-party provider is assumed to attest human identity.

## What source was added (not deployed)

`mail-verifier/cloudflare-email-routing-readonly.mjs` is a library, **not**
a Worker deployment entrypoint. No `wrangler deploy`, DNS, MX, Resend
webhook, Supabase, signing secret, API endpoint, production message handler or
Android change was made.

- Explicitly requires a synthetic `scope` marker and a recipient domain
  containing an exact `test` subdomain label.
- Reads `message.from` (SMTP MAIL FROM) separately from the untrusted
  RFC5322 `From` header, so an envelope sender cannot overwrite the visible
  author.
- Parses a narrow `mx.cloudflare.net` Authentication-Results shape only.
  Missing, duplicate, ambiguous, malformed or non-Cloudflare authserv headers
  become `not_checked`. It does NOT trust sender-inserted raw MIME headers.
- Retrieves raw MIME from a bounded stream (5 MiB cap) and returns only its
  SHA-256, not the email body, attachment contents or private keys.
- Extracts the untrusted Reply-To claimed address as a **caution signal**,
  including mismatched domains and unparseable/ambiguous multi-recipient cases.
  A downstream synthetic-only integration test feeds this into the existing
  `BharatMailTrustEngine.inspect()` Reply-To warning.
- Returns upstream result strings as OFFLINE mock observations only. Hard-coded
  `live_sender_domain_verified:false`,
  `sender_identity_verified:false`,
  `organization_authority_verified:false`,
  `payment_beneficiary_verified:false`,
  `production_authorized:false`.
- Does not call fetch, send, forward, reply, update DNS or write storage.

The module cannot authenticate its caller when invoked in Node tests.
**An `mx.cloudflare.net` string in an arbitrary HTTP request, user metadata
or email content must never grant Cloudflare origin authority.** Genuine
provenance can only be established by deploying under Cloudflare's internal
`email()` handler and reviewing its delivery / routing / authorization
boundary. Never elevate these OFFLINE strings into the existing signed sender
report schema or production UI.

## Automated verification

[GitHub Actions #41836397487](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41836397487):
**2/2 jobs successful, 230/230 Node tests PASS, zero failed/skipped.**

- 74 mail-verifier Node cases, including **16 newly added Cloudflare-shaped
  mocked-worker and Reply-To integration/adversarial tests**.
- 155 prior Mail Trust Engine and device/security regression cases.
- 1 genuine local IPv4 SMTP to disposable PostgreSQL crypto/replay test.
- PostgreSQL 17 synthetic immutable key/receipt policy and 24 parallel
  replay/idempotency requests pass as separate SQL/shell checks.

These are synthetic tests, **not real Cloudflare Worker invocations** and
not actual Internet-received emails. They do not prove end-to-end sender
authentication, trusted Cloudflare origin or operational integration.

## Safest path to a real pilot (requires operator account action)

1. **Do not enable Cloudflare Email Routing on `bharathlink.com` or alter
   its current Resend MX records.** Cloudflare normally manages MX during
   onboarding. A provider collision could silently disrupt real inbound mail.
2. Have an authorized operator prepare an **independent test DNS zone /
   domain** already on Cloudflare DNS, or independently confirm safe isolated
   subdomain routing without changing apex MX. A subdomain setting may depend
   on first enabling zone-level apex routing; therefore do not assume it is
   isolated merely because the email address includes `test`.
3. Create a read-only/staging Worker `email(message,env,ctx)` handler on
   that test zone only, behind a reviewed routing rule. Avoid a no-op Worker
   for real mail: unhandled mail can be dropped/rejected.
4. Send controlled harmless messages from multiple known test senders,
   including SPF-only, DKIM-only, failed DMARC, Reply-To mismatch and forged
   Authentication-Results. Capture only redacted platform auth verdicts and
   bound original MIME hashes; check exact arrival/recipient evidence.
5. Design a separate **server-to-server signed report** from the trusted
   Cloudflare worker to BharathLink with scoped signer keys, timestamp,
   nonce/replay ledger, independently authorized recipient and original raw
   SHA-256. Do not reuse client-supplied header strings as signatures.
6. Conduct external security review and recipient/domain coverage audit.
   Domain auth ≠ human/legal identity ≠ authority ≠ safe payment.
7. After separate user/operator authorization and a delivery-safe migration
   plan, discuss controlled rollout. Until then all production trust badges
   and Android release gates remain HOLD.

## Release gates

- No real Cloudflare account, zone, inbound Worker or email verified here.
- No independently audited provider-to-BharathLink signed report exists.
- No production SPF/DKIM/DMARC result has been emitted to a user.
- No user email, financial data, production API token, phone signing key or
  live Supabase/Netlify/Resend/MX configuration was touched.
- `MAIL_AUTH_RELEASED=false`, Play Protect clearance, Android signer
  continuity and independent identity-issuer review remain unresolved.

**Final decision: isolated source + synthetic CI PASS; real receipt AUTHORITY
UNVERIFIED; production release HARD HOLD.**
