# BharathLink Mail — Signed SMTP SPF, DKIM and DMARC Verification (OFFLINE / HARD HOLD)

**4 November 2026** | Branch `bharathlink-mail-smtp-spf-dmarc-offline-ci`

## Independently verified CI

- [Latest GitHub Actions run #41824239638](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41824239638) — **2/2 jobs SUCCESS**.
- **27/27 offline mail authentication tests PASS** (13 prior real RSA-2048 DKIM tests + 14 new signed-SMTP SPF/DMARC tests) and **142/142 existing Mail Trust / security regression tests PASS**. Total **169/169**, zero fail/skip.
- All SMTP identities, DNS TXT records, RSA/P-256 keys and received raw email bytes in CI are synthetic. No real user email or live DNS was queried.

## Implemented architecture

1. `mail-verifier/verify-signed-smtp-receipt.mjs`: canonical P-256 signed receipt binds provider message ID, exact sender and recipient, actual raw MIME SHA-256, connecting SMTP IP, MAIL FROM, HELO, receiver MTA, receipt timestamp, expiration and nonce. The pinned receiver public key must come from **independently audited operator configuration**, never message metadata. Rejects forged/expired/other-recipient/wrong-content receipts before DNS.
2. `mail-verifier/verify-smtp-spf-dmarc.mjs`: uses **mailauth@8.0.0** with strict RFC mode to evaluate real SPF, DKIM and DMARC algorithms using an explicitly supplied SMTP envelope and independent DNS resolver. Critical `trustReceived:false` prevents forged `Received` headers from supplying client IP/HELO. DNS query counts and outputs are bounded; DNS outages, invalid raw MIME and unavailable signed receipts cannot promote a sender.
3. A conservative extra gate requires exactly one parseable raw `From` mailbox, an SPF PASS with the **exact same author-domain** or full-body DKIM PASS aligned with the exact author domain, a real published DMARC policy and policy `PASS` before returning a *synthetic-only* domain-authentication success. Normal DMARC relaxed organizational alignment that does not satisfy this stricter gate remains unverified, not falsely marked PASS.
4. `mail-verifier/tests/spf-dmarc-offline.test.mjs`: genuine SPF+DKIM+DMARC pass, SPF fail with DKIM pass, SPF pass from unaligned envelope, unsigned forged `Received`/`Return-Path`/`Authentication-Results`, missing DMARC, malformed/multiple From, unsigned changed raw MIME, P-256 issuer substitution, wrong tenant/recipient, expired/future receipt, DNS outage, oversize input and DKIM body-length `l=` suffix injection.
5. `.github/workflows/bharatmail-spf-dmarc-offline-ci.yml` has two isolated jobs: actual mailauth cryptographic/RFC tests with synthetic DNS and all prior Mail Trust + device security regression checks. There is no deploy/build/upload job.

## What this does NOT authorize

- **No actual receiving SMTP gateway is integrated.** The existing live Resend inbound webhook can prove receipt-event origin, not the claimed sender's connecting IP or envelope MAIL FROM. Sender-controlled headers may be forged. A signed test receipt from a newly generated synthetic key does **not** establish ownership or legal trust in any real receiving service.
- Independent receiver operation, verified connection-IP and envelope provenance, key custody/rotation/revocation, DNSSEC or appropriately trusted DNS resolution, abuse resistance, public-suffix / relaxed DMARC handling, real mail QA and external pen testing remain necessary.
- Even a genuine domain SPF/DKIM/DMARC PASS authenticates domain-level email behavior, not a person, organization authority, payment request safety, or a specific link.
- No live Supabase table/function/Edge deployment, Resend webhook, Netlify site, Android signing, APK or first-device trust grant changed. Existing `MAIL_AUTH_RELEASED=false`, KeyPrep and Play Protect release holds remain intact.
- The existing browser UI continues to display SPF/DKIM/DMARC **not checked**, because the actual live receiving identity gateway has not been provisioned.

## Source-to-production trust contract

A future security-reviewed receiver must provide independently validated SMTP connection IP and envelope MAIL FROM with a P-256 signed receipt bound to the actual raw MIME hash and routed message, must have its **receiver public key pinned** outside email content and private key under secure independent custody, must enforce replay handling and retention, and must run trusted DNS verification. Only a reviewed release change may promote a verified domain-authentication result, while identity and payment authority remain separate.

**Verdict: Complete staged offline SPF/DKIM/DMARC cryptographic/RFC pipeline with synthetic receiver evidence; live sender verification remains HOLD.**
