# BharathLink Mail — Actual Cloudflare Wrangler Local Email Handler (SOURCE ONLY / HARD HOLD)

**4 November 2026** · Branch: `bharathlink-mail-cloudflare-pilot-handler-local-ci`

## Executive result

**PASS**: [GitHub Actions #41839305792](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41839305792) — **3/3 CI jobs PASS, 242/242 Node tests PASS, 0 failures/skips**, plus PostgreSQL 17 disposable security assertions and 24 concurrent replay attempts PASS.

**A real local Cloudflare Wrangler 4.157.0 runtime invoked the Worker `email(message,env,ctx)` handler from an RFC5322 test message at the documented `/cdn-cgi/local/email` endpoint.** Default configuration was DISABLED; the handler explicitly rejected the synthetic event and never forwarded it. This is stronger than simply mocking a JavaScript event, but it is *still a LOCAL simulation*, not proof of delivery from a real Internet SMTP peer or real Cloudflare MX.

The first full-runtime attempt used a named export (a constant) in the Worker entrypoint. Wrangler correctly rejected it because Workers entrypoints cannot expose non-handler named exports. The source was fixed by extracting all test helpers into a separate module and keeping only `export default handler` in the Worker entrypoint. The final 3-job CI succeeds.

## What was implemented

### Actual Cloudflare email() entrypoint

- `mail-verifier/cloudflare-pilot-worker.mjs` is an actual Workers module entrypoint using the supported `email(message,env,ctx)` handler and default export only. It performs **no HTTP fetch**, user WebSocket, chat, payment or outgoing-sending API calls.
- `mail-verifier/cloudflare-pilot-helpers.mjs` contains separately testable validation, bounded raw MIME SHA-256 evidence and conservative Cloudflare `Authentication-Results` parsing. It imports pure bounded helpers from the existing read-only Cloudflare adapter.
- **Default worker is intentionally disabled**. To even enter the staged forwarding branch, an independently authorized administrator would need to configure all of `BLMAIL_PILOT_MODE=isolated-test-forwarding-only`, an exact recipient address with a `test` DNS label, a matching independently pinned `BLMAIL_TEST_ZONE`, and a distinct controlled `BLMAIL_TEST_SINK`. The real destination must first be verified with the receiving provider. No such live settings exist here.
- The handler requires `message.canBeForwarded===true`, bounded `rawSize`, exact configured recipient and distinct recipient/sink domains. On unconfigured, unauthorized, oversize or failed-forward cases it calls `message.setReject` instead of silently swallowing a routed email.
- **Delivery-before-inspection:** in the authorized *test* branch it forwards exactly once to the distinct test mailbox, then best-effort checks the unmodified raw MIME SHA-256. If evidence parsing fails *after* delivery, it does not retroactively reject or forward twice. All test environments use mocked forwarding, not real email.
- Logs only coarse result names and domain-authentication observations. No sender or recipient address, raw MIME, URL, attachment, private signing key, API secret or full SHA-256 digest appears in Worker logs. Raw digest stays in memory and is not posted anywhere.
- **No receiver signer exists; no signed trust report or Supabase write is generated.** The Cloudflare-generated `Authentication-Results` header must be read inside genuine provider-controlled `email()` runtime after independently authorized MX routing; arbitrary HTTP/JSON/header strings do not prove provenance. All existing synthetic signals remain `not_verified` for human identity/authority and payment beneficiary.

### Local Wrangler configuration and real runtime test

- `mail-verifier/wrangler.local.jsonc`: actual Wrangler config with `BLMAIL_PILOT_MODE=DISABLED`, `workers_dev:false`, `preview_urls:false`, and **no route, webhook, service binding, database, storage, send-email or production credentials**.
- `mail-verifier/fixtures/cloudflare-email-worker-smoke.eml`: harmless synthetic RFC5322 email with Message-ID and a forged sender-controlled `Authentication-Results` header; used only for local simulation.
- `mail-verifier/tests/cloudflare-pilot-worker.test.mjs`: **12 new Node tests** covering default reject, exact forwarded sink once, safe log redaction, raw SHA-256 binding, envelope/recipient restrictions, spoofed/malformed authentication headers, forward failure, post-forward evidence failure, oversized messages, no network/send/reply, and the Cloudflare default-handler export boundary.
- `.github/workflows/bharatmail-cloudflare-pilot-handler-local-ci.yml`: 3 independent jobs:
  1. 86/86 Mail SMTP/Cloudflare/cryptographic tests + 155/155 existing Mail/Android security tests
  2. Real local `wrangler@4.157.0 dev` launched without deployment/authentication credentials, `curl` sent a synthetic email to `127.0.0.1:8787/cdn-cgi/local/email`; CI found explicit `BLMAIL_TEST_REJECT:gated` and no `BLMAIL_TEST_FORWARD_OK_NO_SENDER_VERIFICATION`
  3. 1/1 real 127.0.0.1 SMTP → P-256 → disposable PostgreSQL integration test + SQL key/revocation/owner checks + 24 parallel nonce replay/idempotency requests

## What has NOT happened

- No Cloudflare account has been connected, no real email has been received from the public internet, no Cloudflare MX has been configured and no actual Cloudflare `email()` execution in a remote provider zone has been observed.
- No change to existing `bharathlink.com` or `bharathlink.in` Resend MX records, DNS zones, Netlify hosting, Supabase DB/functions, production secret, VAPID key or Android APK.
- No production SPF/DKIM/DMARC result, real verified sender identity, authority/organization license, safe link or verified payment beneficiary was proven.
- No auto-upload, auto-forwarding of real customer email or user-visible verified badge.
- Existing `MAIL_AUTH_RELEASED=false`, Android Play Protect, signer/key-custody and independent identity issuer HOLD remain unchanged.

## Critical operator warning

**DO NOT `wrangler deploy` or add this Worker to any real routing rule.** In its default DISABLED mode, if mistakenly attached to a live inbound mail route, the Worker explicitly rejects that mail. Its presence on GitHub is not permission to deploy it. First establish an independent TEST zone, confirmed delivery-safe existing MX baseline, verified test sink, privacy approval, provider key custody and an operational incident/rollback plan.

Cloudflare's current docs say Email Routing manages MX records and may conflict with external mail providers at the zone apex. Subdomain onboarding can also depend on zone-level routing conditions. Therefore an `@test.bharathlink.com` address **alone** does not prove safe isolation. Use an explicitly audited separate test zone or an equivalent verified non-disruptive topology.

## Evidence and official references

- Cloudflare Workers email handler and platform-prepended first Authentication-Results: https://developers.cloudflare.com/email-service/api/route-emails/email-handler/
- Cloudflare `wrangler dev` simulation of incoming email (no MX): https://developers.cloudflare.com/email-service/observability/local-development/routing/
- Cloudflare current subdomain workflow: https://developers.cloudflare.com/email-service/configuration/subdomains/
- Cloudflare external MX conflict/possible delivery disruption: https://developers.cloudflare.com/email-service/reference/troubleshooting/

**Final: LOCAL RUNTIME AND AUTOMATED CI PASS; REAL INTERNET SMTP AUTHENTICATION AND PRODUCTION RELEASE STILL HARD HOLD.**
