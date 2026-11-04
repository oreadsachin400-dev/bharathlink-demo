# BharathLink Mail — Inbound Sender Authentication Boundary Audit

**4 November 2026 | Source and read-only Supabase TEST audit | NO LIVE CHANGES**

## Current working code path (read-only confirmed)

- The existing `bharatmail-inbound-webhook` Supabase Edge Function (deployed TEST version 8 as inspected) requires the **Svix-signed Resend `email.received` event**. It checks timestamp freshness and HMAC over the webhook body, stores an inbound event, then retrieves the email through Resend's Receiving API server-side. These checks authenticate the webhook delivery **to the configured Resend signing secret**. They do not prove that the claimed sender is a real person or that the sender domain is authenticated.
- The webhook fetches the message body from `/emails/receiving/{id}` but currently does **not** store or independently validate trusted receiver-computed SPF/DKIM/DMARC authentication results. The untrusted sender's own `Authentication-Results` headers must NOT be treated as validated evidence. Do not mistake a validated webhook signature for validated email-sender identity.
- The `public.bharatmail_inbound_events` table includes `authentication_status` with default **`unverified`**, plus `authentication_source` and `authentication_checked_at`. The routing function `public.bharatmail_route_inbound_event(text)` rejects a record with `authentication_status='fail'`, but currently permits `unverified` to proceed when its separate reply-token/routing checks pass. Thus **unverified mail can appear as inbound mail**. It should remain visibly **Unverified**, even when it has an exact reply-route token and From-address match.
- The `public.bharatmail_external_messages` table currently has **no trusted SPF, DKIM, DMARC or Reply-To fields**; its client query receives `from_address`, subject and body metadata. Those are not authoritative identity proof.
- A distinct `bharatmail-external-send` Edge function sends email; sending success or a sender-owned DKIM signature is not evidence that a received request is safe.

## v1 mitigation implemented in the GitHub application source

- `bharatmail-trust-engine.js`: no data upload, phishing/impersonation/link/payment heuristics, never marks a sender safe, genuine, or fake with certainty.
- Main `index.html` inbox list and message-detail panel show **Suspicious**, **Check sender and links**, or **Sender not verified** with concrete explanations.
- The previous **verified external email endpoint** badge based solely on the spoofable `From` string was removed for inbound external mail.
- Domain authentication, sender identity, organization authority, and payment request are each shown as **not verified/not checked**, independently of other signals.
- [GitHub source tests #41812067141](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41812067141) completed **23/23 Mail Trust tests** plus **91/91 existing security-contract tests**, no fail/skip.
- The source is **not deployed** to Netlify, Supabase or a phone. It changes no receiving-Mail SQL data and does not reactivate any currently disabled native-device approval path.

## Minimum requirements before claiming a receiver-verified domain

1. Select an authoritative, documented server-side provider verification source. Either **perform independent SPF/DKIM/DMARC verification over reliable raw SMTP receipt metadata and raw signed MIME content**, or consume a verified receiver-generated authentication result with a clearly documented trust boundary and anti-header-injection controls. The message author's untrusted `Authentication-Results` headers are never authoritative.
2. Ensure the webhook origin is verified, event identity cannot be replayed to rewrite results, and the Resend Received Email ID is bound to the exact stored message/recipient and its immutable sender address. Take care: Resend `email.received` webhooks contain metadata, not the full body/headers. The server's Received Email GET is a separate step.
3. Store immutable or tightly privileged **server-only** evidence for authenticated domain, aligned From domain, SPF/DKIM/DMARC results and timestamps. Keep it in a separately controlled table with **owner-only SELECT under RLS**, no insert/update from public clients; maintain provenance and retention policies. Never let the client override it with `verified:true`, spoofed headers, or a directory match.
4. Define exact consequences: authentication failures trigger warnings/quarantine review; **DMARC PASS is not legal identity verification**. Real-world sender/person/org roles require independent issuer authority; payment beneficiary matches require an authorized payment provider.
5. Add adversarial tests: forged `Authentication-Results`; misaligned DMARC; forwarded mail/ARC cases; unicode lookalikes; multiple From/Reply-To headers; webhook replay and stale timestamp; races; attachment injection; incorrect tenant/recipient access; and legitimate unsigned mail with cautious labeling.
6. Run a fully isolated disposable Postgres + mocked provider/Edge integration and independent security review before any TEST rollout. Physical Android and real inbox QA follow the separate app release policy.

## Official provider technical references

- [Resend Receiving API](https://resend.com/docs/api-reference/emails/get-received-email)
- [Resend inbound webhook flow](https://resend.com/blog/inbound-emails)
- [Resend's published receiving guide](https://github.com/resend/resend-skills/blob/main/skills/resend/references/receiving.md)
- [Supabase Edge Functions](https://supabase.com/docs/guides/functions)

## What remains unresolved

**Authoritative SPF/DKIM/DMARC verification, real sender/organization identity, trusted payment request verification, live web QA and deployment**. Source-only heuristics can warn but must never auto-block legitimate messages or claim an official sender is authentic. All unrelated Play Protect, KeyPrep signing and first-device enrollment release HOLDs remain intact.
