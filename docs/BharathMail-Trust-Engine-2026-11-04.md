# BharathLink Mail Trust Engine v1 — explainable fake-sender warning layer

**Date:** 4 November 2026  
**Branch:** `bharathlink-mail-trust-engine-staged-ci`  
**Status:** SOURCE IMPLEMENTED + OFFLINE CI ONLY. Not deployed to Netlify or Supabase; no new Android APK.

## What was actually added

- New `bharatmail-trust-engine.js` local deterministic inspection module.
- Existing full `index.html` loads this module **before** the main app script.
- New **BharathMail Sender Trust** panel on received-mail detail pages, plus a concise warning label in inbox rows.
- Four independently unverified trust dimensions: sender domain authentication, sender identity, organization authority, and the legitimacy of any payment request.
- Signals for malformed From addresses, organizational/authority names using generic public inboxes, internationalized/punycode domain names, potentially lookalike security/login naming, Reply-To domain mismatches, requests to share OTP/password/PIN/CVV (including a second-clause scam after a protective disclaimer), urgent money requests, HTTP/shortened/disguised-IP links, and risky link/request combinations.
- Multiple reasons are displayed as plain DOM text using the application's existing safe `h(...)` element builder. No external model, email-body upload, automatic spam/deletion action, or external URL fetch.
- Fixed a misleading existing directory match: **incoming external email no longer receives a "verified email endpoint" UI badge merely because a spoofable From address matches a directory entry.** Existing verified internal BharatMail endpoint display is preserved.

## User-facing behavior

- **Suspicious · verify before acting**: local high-signal markers such as credential harvesting, public-mail authority impersonation, concealed destination, or urgent payment.
- **Check sender and links**: heuristic medium signals such as mismatched Reply-To or shortened/insecure link.
- **Sender not verified**: ordinary emails and those with no flagged content, **never a "Safe" or "Verified" badge**.
- Every incoming external message explains that **SPF/DKIM/DMARC have not yet been independently verified by the receiving server**. Untrusted `Authentication-Results` headers or user-controlled message metadata must not elevate the status.
- Receiving mail using the internal BharatMail channel does not imply verified legal identity or authority.
- "Verified" must NEVER be inferred from a From email string, directory match, sender-controlled header, payment QR, display name, or a successful email delivery.

## Existing backend compatibility and missing production infrastructure

Live TEST schema was inspected read-only on 4 November 2026: the existing external-message table does **not** contain trusted SPF/DKIM/DMARC columns or a Reply-To column. No schema or user rows were changed. The existing live frontend obtains external messages with a Supabase RLS-protected REST query to `bharatmail_external_messages`. Its selected fields include `from_address`, `subject`, `body`, `html_body`, etc., but **no cryptographically authenticated receiver-computed SPF/DKIM/DMARC result** and no independent third-party issuer/representative authority evidence. Thus this version uses only heuristic warning signals; it **cannot prove an email address fake, prove a human identity, prove authorization, or clear a message as safe**.

The `reply_to` check is implemented in the standalone trust engine but requires a trusted server-supplied Reply-To field in real received email records to be active for the existing live external-mail UI. Without it, the check remains unavailable and is not claimed tested end-to-end.

For real SPF/DKIM/DMARC verification, a **separate independently reviewed inbound mail trust pipeline** would need to validate the receiving provider/webhook origin, retrieve raw envelope/header/authentication evidence from the receiver, independently validate a reliable receiver-computed result (not arbitrary sender-supplied `Authentication-Results`), store tamper-resistant results under owner-restricted RLS, and enforce replay prevention and privacy retention. DMARC PASS still does not prove personal identity or request safety. Resend's `email.received` webhook supplies metadata; retrieval API is used for body/headers, and the webhook must be signature-checked. None of these server steps have been enabled by this phase.

Independent issuer-backed identity, organization role delegation and recipient/payee owner verification are future components requiring appropriate third-party providers and governance. Do **not** connect a live payment/OTP trust grant from these local heuristics.

## Test coverage and release guard

`tests/bharatmail-trust-engine.test.mjs` contains **23** Node.js cases including negative SPF/DKIM/DMARC claims, public-mail authority impersonation, malformed sender, lookalike domain, shortened links, HTTP or IP destinations, secrets, urgent money, Reply-To differences, bounded untrusted content, no network transmission, and HTML syntax/UI integration.

`.github/workflows/bharatmail-trust-engine-ci.yml` performs Node syntax and tests with no Supabase deploy, Netlify publish, APK build/upload, or production data access.

## Remaining checks before actual TEST availability

1. Review UI appearance on actual Android and web browsers; no real physical screenshot/QA is implied by source syntax tests.
2. Keep `index.html` and `bharatmail-trust-engine.js` together when building a **reviewed future TEST deployment**. If the script cannot load, the UI falls back to **Verification unavailable**, never Verified.
3. Perform regression tests of internal BharatMail send/receive, external inbound inbox/detail, attachments, message actions and E2EE unaffected by this UI-only addition.
4. Build separately reviewed backend receiving-authentication verifier, access controls, trust registry, fraud feedback and false-positive dispute workflows before offering authoritative "Domain Authenticated"/"Identity Verified"/"Authority Verified".
5. No other pending release HOLD is altered: Google Play Protect, installed KeyPrep signing continuity, independent identity issuer and first-device authorization remain blocked.

**Verdict:** First functional BharathMail Mail Trust UI + local warning engine are integrated into the main GitHub source, but actual email identity verification, trusted SPF/DKIM/DMARC, live deployment and physical Android QA are **not complete**.

## Final CI checkpoint

- [GitHub Actions run #41811978333](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41811978333) **SUCCESS**.
- New Mail Trust Engine: **23/23 tests PASS, zero failure/skip**.
- Existing security/source regression: **91/91 tests PASS, zero failure/skip**.
- Combined: **114/114 offline Node.js tests PASS**.
- HTML inline JavaScript parsed successfully, external spoofable From no longer elevates identity via directory badge, and all trust dimensions remain unverified without genuine server validation.
- No live Supabase, Netlify, Android APK, SMTP, payment provider, or authoritative identity changes.

This is not a server-side SPF/DKIM/DMARC test, actual web/Android visual QA, or production acceptance test.

## Latest receiving-authentication audit and CI checkpoint

- [Verified offline run #41814453029](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41814453029): **24/24 Mail Trust tests + 91/91 existing security regression tests = 115/115 PASS**, zero failures and skips.
- Read-only Supabase TEST inspection confirmed the deployed inbound Resend webhook's **Svix signature check** authenticates the webhook, not the sender's SPF/DKIM/DMARC or legal identity.
- The existing `bharatmail_inbound_events.authentication_status` defaults to `unverified`; current routing can accept `unverified` mail after its separate reply-token checks. The client must **never** label such mail as authenticated based on the received `From` field.
- Reviewed source/security boundary: [BharathMail inbound authentication audit](https://github.com/oreadsachin400-dev/bharathlink-demo/blob/bharathlink-mail-trust-engine-staged-ci/docs/BharathMail-Inbound-Auth-Boundary-Audit-2026-11-04.md).
- `docs/security-release-readiness.json` now explicitly records **Mail Trust source implementation PASS but production release HOLD**, with real SPF/DKIM/DMARC, sender identity, organizational authority and payment recipient verification all unverified.
- **No live mail, Supabase, Netlify, app signing, Android APK or first-device identity changes.** The feature remains a reviewed, tested GitHub source implementation awaiting a future controlled TEST deployment.
