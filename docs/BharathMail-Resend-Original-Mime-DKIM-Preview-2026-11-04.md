# BharathLink Mail — Resend Original-MIME DKIM Domain Check / On-Demand UI (HOLD)

**4 Nov 2026 | Branch `bharathlink-mail-resend-real-dkim-on-demand-preview` | Source only — not deployed.**

## Real operating context verified via connected Supabase (read-only)

Production `BharathLink Demo` Supabase project currently has **3 inbound external mail records**, last received **26 Oct 2026**, and **all 3 inbound events have `authentication_status=unverified`**, with no independent `authentication_source` populated. The deployed `bharatmail-inbound-webhook` function version 3 validates the Resend Svix webhook signature, retrieves Resend Receiving API content and routes the message. It **does not independently verify the sender's DKIM signature**. No user email contents, email addresses, or keys were exported for this audit.

**Faster path:** Don't move existing email MX from Resend to Cloudflare merely to gain **a narrower cryptographic DKIM domain-signature proof**. Resend's authenticated Receiving API exposes the original MIME via a short-lived signed raw URL. Download those exact original bytes server-side, compare the API metadata to an already-owned incoming mail row, independently fetch the signer key from public DNS, and verify the actual DKIM signature. This can verify a *signing domain*, not a real person, registered authority, whole SMTP session, SPF or full DMARC alignment.

## Implemented (no live deployment)

1. `supabase/functions/bl-mail-auth-attest/resend-raw-evidence.mjs`: reuses existing bounded 5-MiB Resend original-MIME retrieval with fixed provider API host and operator-set raw-download hostname allowlist. New server-only `getBoundRawMime` retains a temporary byte buffer for cryptographic signature checks. Original `getBoundRawSha256` remains unchanged to its callers and zeroizes its buffer. Redirects, expired capability URLs, metadata mismatch, oversized streams and arbitrary raw URLs fail closed.
2. `mail-verifier/verify-resend-received-dkim.mjs`: calls existing real RSA/Ed25519 DKIM verifier based on pinned `mailauth@8.0.0`. Independently queries a fixed public DNS-over-HTTPS resolver (`cloudflare-dns.com`) for `selector._domainkey.fromdomain` public TXT keys only, with bounds, timeout, exact owner checking and no redirects. Verifies the canonicalized original MIME signature, From binding, strict alignment and body-coverage limits. Always zeroizes original MIME bytes after processing.
3. `supabase/functions/bl-mail-dkim-preview/index.ts`: proposed **separate user-initiated read-only Supabase Edge function**. It authenticates the real user JWT, checks user-owned inbound message through existing RLS (not `service_role`), then independently retrieves that message's original MIME using server-only Resend credentials. No SQL changes, writes, mail re-routing or background polling. Exact allowlisted browser origin, JWT, 512-byte request cap and explicit `BL_MAIL_DKIM_PREVIEW_MODE=owner-scoped-test-enabled` opt-in required.
4. `supabase/functions/bl-mail-dkim-preview/deno.json`: Deno pin for `mailauth@8.0.0`. CI proves Edge TypeScript/Deno import and typecheck succeed.
5. `index.html`: existing incoming external mail detail view now includes **Check DKIM domain signature (TEST)**. It sends the owned message UUID to the guarded Edge endpoint (no email contents in request). Response differentiates an actual strictly aligned DKIM domain-signature pass from no verified proof, while clearly marking **sender identity, authority, payment request, SPF and DMARC as NOT independently verified**. On missing backend, signed-in session or unavailable provider it fails closed with a nonverified status.
6. Adversarial tests verify valid signed original MIME and real RSA-2048 public key proof, unsigned/self-claimed `Authentication-Results` fraud, tampered MIME, wrong DNS keys, metadata swaps, raw URL SSRF attempts, TXT ambiguity, DNS outage and domain-only labeling.

**CI:** [Run #41842124967](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41842124967) — **2/2 jobs PASS: 150/150 targeted Node tests PASS (97 mail crypto incl. 11 new, 53 UI/Resend regression), Deno Edge function typecheck PASS.** This is **synthetic/offline CI**, not successful live verification of the three stored inbound emails.

## Exact real-world gate — no new Cloudflare MX needed

Operator-controlled steps needed for a **real authenticated TEST check**:
- Independently validate that the Resend `RESEND_INBOUND_API_KEY` secret in production Edge remains current and can retrieve the three known inbound Resend message IDs. Existing webhook historically used the key; present validity is not proven by static source.
- Discover the legitimate exact `raw.download_url` hostname returned by Resend Receiving API **inside a server environment without printing signed capability URLs**, and set `BL_MAIL_RAW_DOWNLOAD_HOSTS` to that exact hostname. No arbitrary wildcard allowed.
- Set `BL_MAIL_PREVIEW_ALLOWED_ORIGINS` to the exact HTTPS URL(s) of the controlled TEST PWA host (not `*`) and enable `BL_MAIL_DKIM_PREVIEW_MODE=owner-scoped-test-enabled` in a reviewed test scope. Never expose a Resend or service-role key in browser JS.
- Independently review and explicitly authorize deploying the separate Edge function `bl-mail-dkim-preview` with `verify_jwt=true` and its required files/dependency map. Keep the existing `bharatmail-inbound-webhook`, live DB, and Resend MX untouched.
- After test launch, log in to the rightful account and click **Check DKIM domain signature (TEST)** on one already-received external email. Confirm real provider fetch, DNS query, strict signature evidence, and negative/cross-user denial. Avoid logging private content. A missing/expired Resend raw file must yield **not verified**, not a false failure claim.
- Perform security review before promoting any domain-authentication result to production. No artificial 'Verified Person', 'Safe', 'Official Bank' or 'Trusted Payment' badges based on DKIM.

## Remaining blocker

The connected Supabase management tools can inspect existing tables/functions but do not expose the existing Resend API secret value or a list of configured Edge secrets; the separate Edge endpoint has **not been deployed or enabled**. A live signed MIME sample has not been processed. Test implementation and code compilation do not prove live sender authentication.

**Release decision: HOLD.** Existing hard release gates for Android Play Protect, signer/key custody, identity issuer and real SPF/DMARC remain intact. No production schema, DNS, Netlify, Resend or APK changes in this branch.

References:
- Resend inbound: https://resend.com/features/inbound
- Resend official SDK ReceivedEmail.raw metadata: https://github.com/resend/resend-go/blob/main/receiving.go
- Supabase Edge packages: https://supabase.com/docs/guides/functions/dependencies
