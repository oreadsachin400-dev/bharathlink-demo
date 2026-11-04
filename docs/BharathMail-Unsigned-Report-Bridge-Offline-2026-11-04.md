# BharathMail — Offline SPF/DKIM/DMARC → Signed-Report Schema Bridge (HOLD)

**4 November 2026** | Branch: `bharathlink-mail-verified-report-bridge-offline-ci`

## Purpose

Join the existing real cryptographic/RFC SPF, DKIM and DMARC **synthetic**
verification pipeline to the existing server signed-authentication report
schema without silently converting forged emails or untrusted input to a
verified sender.

## What is implemented

- `mail-verifier/derive-offline-unsigned-auth-report.mjs` invokes the
  existing `verifySmtpDomainAuthentication` from original MIME bytes,
  an independently pinned P-256 receiver receipt, trusted SMTP envelope
  parameters and explicitly supplied DNS lookup.
- Converts only real observed RFC results to exact `validateReport`
  schema fields; absent/unknown results map to `none`, never `pass`.
- SPF identity is the verified SMTP MAIL FROM domain, which can differ from
  RFC5322 From. An unaligned SPF PASS does not imply DMARC PASS.
- DKIM PASS is mapped only for a full-body cryptographic signature strictly
  aligned to the author From domain. DMARC PASS requires the evaluator's
  qualified strict domain match.
- The output is **UNSIGNED**: no issuer key is created, loaded, exposed or
  provisioned in the application module. The downstream synthetic report
  issuer identifier must be supplied explicitly and must differ from the
  SMTP receiver's signing-key identifier. The integration test generates
  ephemeral synthetic issuer keys in memory to check that the existing
  signed-report consumer accepts the exact bound schema.
- Receipt provider ID, sender, routed recipient, MIME SHA-256, nonce and
  expiration are carried into the report.
- No local verification may claim human identity, organization authority,
  a safe payment beneficiary or an approved receiving SMTP gateway.

## Scope and blockers

This code is not called by any deployed service. There is **no real SMTP
receiver**, no confirmed trusted connecting IP or envelope in live Resend
webhooks, no audited public-key pin, no independent private-key custody, no
real DNS QA, no real email test, and no approval to distribute or activate
sender verification. Existing `MAIL_AUTH_RELEASED=false` and production,
KeyPrep, Play Protect, device and Android release HOLD gates remain intact.
The receipt nonce binds the synthetic report, but this library does **not**
provide a durable replay store. Existing staged SQL has separate atomic
replay handling; actual operator storage and deployment require review.

## Tests

`mail-verifier/tests/unsigned-report-bridge-offline.test.mjs`
has ten integration/adversarial checks: exact strict SPF/DKIM/DMARC,
ephemeral signed-report interoperability, unaligned SPF, DKIM-only DMARC,
forged Authentication-Results/Received, tampered raw MIME, wrong pinned
receiver key and recipient, DNS outages/missing DMARC, missing input, and rejection of a report issuer key ID that reuses the receiver ID.

[GitHub Actions CI run #41825648953](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41825648953): **2/2 jobs PASS**, **37/37 offline mail tests PASS** (13 DKIM, 14 signed SMTP SPF/DMARC, 10 unsigned bridge integration), and **142/142 prior security regressions PASS**; **179/179 total**, 0 failures/skips. Passing synthetic tests does not establish a production authority.

**Release disposition: HOLD — no live app, backend or APK modifications.**
