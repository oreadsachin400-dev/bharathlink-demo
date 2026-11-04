# BharathLink Mail — Existing Resend Inbound → Real Original-MIME DKIM (TEST)

**4 November 2026** | Branch `bharathlink-mail-resend-live-dkim-readonly`

## The unnecessary Cloudflare dependency was removed for DKIM-only checks

The existing Resend Receiving API already offers a signed, short-lived URL to
the **original raw RFC5322 MIME** in the authenticated GET
`/emails/receiving/:email_id` response. The original DKIM signature can be
verified directly against that MIME and public DNS TXT signing key. There is
**NO reason to migrate MX from Resend to Cloudflare** for this narrowly scoped
cryptographic domain-signature check.

Sources:
- https://resend.com/docs/api-reference/emails/retrieve-received-email
- https://resend.com/features/inbound
- https://supabase.com/docs/guides/functions/dependencies

## Actual connected Supabase state (read-only checks, no private email read)

BharathLink-20-TEST (`fsdusofbpwdrdvgexxyw`) was inspected:
- `bharatmail_inbound_events`: **11** real incoming event rows (6 processed, 5 pending routing), received 18–26 Oct 2026.
- `bharatmail_external_messages`: **9** rows, with 6 inbound, 3 outbound.
- **All 11 incoming events still show `authentication_status=unverified` and no independent authentication source**.
- Existing TEST `bharatmail-inbound-webhook` version 8 is active; it authenticates provider events and stores/forwards content, but does NOT independently cryptographically verify the sender's DKIM identity.
- Original `BharathLink Demo` project (`lhaiwfdzynssgxmtlytl`) separately has 3 stored incoming events, all unverified, and 7 external mail rows; its existing webhook version 3 remains unchanged.

**No user email address, body, recipient ID, Resend token, signed raw capability URL or exact provider email ID was exported or logged.**

## Source implemented

1. `supabase/functions/bl-mail-auth-attest/resend-raw-evidence.mjs`:
   the existing strict bound, exact-host HTTPS Resend original-MIME fetch
   now exposes an **explicit server-only, ephemeral `getBoundRawMime`**
   while original `getBoundRawSha256` remains digest-only, zeroizing raw bytes.
2. `mail-verifier/check-resend-live-email.mjs`:
   actual server-side Resend API + 5-MiB original MIME verification using
   pinned `mailauth@8.0.0`, independent public DNS TXT lookup and exact
   RFC5322 From / signing-domain alignment. No SQL writes, No MX updates,
   no misleading Verified Sender status; no MIME output in logs.
   CLI requires an operator-held Resend token and independently known original
   email ID/From/To and exact raw-host allowlist. Never put values in GitHub.
3. `mail-verifier/tests/resend-live-checker.test.mjs`:
   6 source tests cover genuine RSA-2048 DKIM signing, altered original MIME,
   forged message-supplied `Authentication-Results`, wrong public DNS key,
   metadata recipient/sender swap and missing credentials. These are
   **synthetic cryptographic tests, not real inbox DKIM results**.
4. `supabase/functions/bharatmail-dkim-check-test/index.ts`:
   separately deployable, read-only Supabase Deno function requiring a
   **verified user's JWT** (platform `verify_jwt=true`), server-validated
   user session, and **existing owner-only RLS policy** on
   `bharatmail_external_messages`. Accepts only `POST` JSON with the
   user's own inbound message UUID. Looks up Resend original MIME server-side,
   verifies RSA/Ed25519 DKIM against bounded public Cloudflare DNS-over-HTTPS
   TXT results, and returns a safe domain-only result.
   - No existing webhook replaced; no SQL or RLS mutation.
   - No public raw MIME, API keys, signed original email URLs or email contents.
   - No SPF claim (SMTP connecting IP unavailable), no DMARC claim,
     no human sender identity, no organization authority, no payment safety.
   - Hard pinned to the **BharathLink-20-TEST project only**, so mistakenly
     trying to deploy it to the original project returns `test_project_only`.
   - Login/RLS enforces mailbox ownership; even a valid JWT for another user
     cannot fetch another user's original email.
   - Full HTTPS raw download is restricted to documented CloudFront / Resend
     host suffixes, rejects redirects and oversized streams.
   - The response is not cached, and MIME copies are zeroized best-effort.
5. `supabase/functions/bharatmail-dkim-check-test/deno.json`: Deno strict
   compile configuration, importing `npm:mailauth@8.0.0`.
6. `.github/workflows/bharatmail-resend-live-dkim-readonly-ci.yml`: prior
   regressions + new real-source bridge cryptographic tests, Deno typecheck,
   Wrangler local runtime disabled-gate check, disposable PostgreSQL replay
   integration. No workflow deploys this function or changes live email.

## Actual deployment completed — to ISOLATED TEST ONLY

**Supabase TEST project `fsdusofbpwdrdvgexxyw`:**
- New `bharatmail-dkim-check-test` function: **ACTIVE, version 1**.
- `verify_jwt=true` confirmed by Supabase management read-back.
- Function endpoint (requires a user bearer access token):
  `https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bharatmail-dkim-check-test`
- No existing `bharatmail-inbound-webhook` was modified.
- No existing production/main Supabase function, Resend MX, DNS or Netlify
  deployment was modified. Android APK unchanged.

**The runtime's first authenticated real message check has NOT yet been
invoked.** Neither the connected Supabase management tool nor the GitHub
connector provides the existing user's JWT or Resend secret, and access tokens
must **not** be pasted into chat. The real Resend token's present validity and
actual raw-email availability are not independently confirmed yet.

The new Edge endpoint is a real running TEST function, but its successful
deployment is NOT proof that any of the 6 inbound TEST messages' original
MIME has been cryptographically checked. Do not mark those 11 records verified
or change the live email UI label based on deployment alone.

## CI

Final GitHub Actions source check:
https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41842647358

- **4/4 jobs SUCCESS**
- **248/248 Node tests PASS (92 mail verifier incl. 6 new + 155 existing
  Mail/Android regressions + 1 localhost SMTP-to-PostgreSQL integration)**
- Deno Edge TypeScript check PASS
- Real local Wrangler Email Worker simulation (default disabled) PASS
- Disposable PostgreSQL 17 key pinning/revocation and 24 concurrent replay
  process checks PASS

## Remaining real end-to-end gate

An authorized user must invoke the new TEST Edge function with an **existing
valid TEST project Auth session JWT** and the UUID of **their own inbound**
`bharatmail_external_messages.id` row, either from an authenticated test
client or a future TEST UI button. Only the UUID is sent, not the original
email body. The endpoint queries user RLS and fetches MIME using existing
server-held Resend credentials. This can yield DKIM domain pass/absence/
verification unavailable, **not** a binary fake email verdict.

A separate source-only UI preview already exists in draft PR #8, but it
targets the original app flow and must be reviewed and reconciled before
deployment. Do not repoint app Auth tokens between two Supabase projects.

**RELEASE DECISION: TEST ENDPOINT ACTIVE ONLY / REAL EMAIL CHECK PENDING /
PRODUCTION AND ANDROID RELEASE HOLD.**

## Update — mobile TEST UI deployed for direct user-owned real-email check

The remaining owner-invocation dependency now has a concrete, mobile-friendly,
**deployed TEST page**:

https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bharatmail-dkim-test-ui

- A NEW Supabase function `bharatmail-dkim-test-ui` is ACTIVE, version 1,
  in project `fsdusofbpwdrdvgexxyw`. Management read-back confirms
  `verify_jwt=false` **for static public HTML only**. The actual DKIM data
  function `bharatmail-dkim-check-test` stays `verify_jwt=true`.
- Public page is served from the Supabase TEST HTTPS origin; it includes
  only a public publishable key and static JS/CSS. No Resend token,
  privileged Supabase key or caller password is shipped to HTML.
- Explicit TEST login supports password or email OTP. OTP request
  specifies `create_user:false` (does not create new accounts).
  Authentication requests go directly from the browser to the same
  TEST Supabase Auth endpoint. Password, OTP and access JWT are never
  sent to the HTML-serving Edge function.
- Access token lives **in JavaScript memory only**; no `localStorage`,
  cookies or `sessionStorage`; refresh requires logging in again.
  Sign-out clears the token and displayed mail rows.
- Authenticated PostgREST list is limited to 30 inbound mail records and
  relies on existing owner-only RLS; sender/subject are rendered using
  `textContent`, not unsafe HTML. Each row has one user-click
  "Check DKIM domain signature" button; it sends only the UUID.
- Strict per-response Content Security Policy includes random
  nonce for inline JS/CSS, `connect-src` to the exact TEST Supabase
  origin, `frame-ancestors 'none'`, `form-action 'none'`, and no third-party
  scripts, iframes or analytics.
- The result explicitly states domain-signature only — a DKIM pass never
  authorizes a "Verified Person", "Official Bank", payment safety or the
  launch of the production sender badge.
- No changes to the original BharathLink app, Resend MX, existing
  external inbound webhook, Android APK or production Supabase project.

**Operator action now reduced to a single browser flow:** open the
above TEST page, log in using the existing BharathLink-20-TEST account,
choose one inbound email and tap the DKIM-check button. The user
should share *only a screenshot or the redacted result state* if feedback
is needed, not email credentials, authorization tokens, original MIME
or full email IDs.

**Limitations:** Deployment status is confirmed through connected Supabase
management read-back, and GitHub CI independently typechecks the source and
its inline JS. A real remote browser GET smoke and an authenticated
owned-mail POST result were NOT available from this assistant's network
environment; these must not be presented as already passed.

**Production release remains HARD HOLD**, and SPF/DMARC plus human/authority/
payment identity remain not checked.
