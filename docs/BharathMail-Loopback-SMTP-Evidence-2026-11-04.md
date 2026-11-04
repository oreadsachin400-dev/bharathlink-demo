# BharathMail — Real Loopback SMTP TCP Evidence (Isolated Test, Release HOLD)

**4 November 2026** — branch `bharathlink-mail-loopback-smtp-receiver-evidence-ci`

## New capability: actual TCP connection provenance (local only)

Before this step, the verifier had cryptographically signed SMTP receipts
assembled from synthetic fixture values. The new source
`mail-verifier/loopback-smtp-test-receiver.mjs` receives a complete
synthetic email over a **real TCP socket bound strictly to 127.0.0.1**
and derives an ephemeral signed SMTP receipt from the connection itself.

This establishes an independently testable source of SMTP connection
and envelope metadata in a controlled CI harness. It does **not**
prove control of a publicly operated SMTP receiving gateway.

The test receiver records:
- `socket.remoteAddress` from the actual local TCP session;
- the SMTP `EHLO`/HELO identity;
- strict single `MAIL FROM` and a single allowed synthetic-domain `RCPT TO`;
- exact SMTP `DATA` bytes after RFC dot-unstuffing;
- one strict parsed RFC5322 `From` header (unsupported folded From is denied);
- a SHA-256 hash of the original received MIME and a short-lived P-256
  signed receipt using a per-test ephemeral key.

The receiver has explicit opt-in guard `BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST=enabled`,
is loopback IPv4 only, supports no TLS, AUTH, external relay, inbound MX,
public port, mailbox storage or production delivery, and closes each test
session after one message. Unrecognized commands, attempted connection-IP
injection via `XCLIENT`, out-of-order commands, malformed senders,
multiple From headers, overlong lines and invalid recipients fail closed.

The existing independent SPF/DKIM/DMARC evaluator verifies a signed receipt
under the expected pinned test public key, and the unsigned report bridge
maps the result only to synthetic authentication evidence. Forged
`Received`, `Return-Path` and `Authentication-Results` fields never supply
the socket IP or envelope MAIL FROM.

## CI and scope

The branch's workflow runs real socket tests and the prior offline mail
cryptography suite, plus the earlier device/security regression suite.
All keys and domains are synthetic; nothing is sent to the real internet.
The receiver's narrow RFC parser is *test fixture code*, not a complete MTA.
No production signal is unlocked, no live DNS read, no user email processed,
no live Supabase/Resend/Netlify changes, no Android APK build or install.

## Still required for genuine live sender/domain authentication

An independently controlled inbound SMTP receiver with correctly deployed
MX routing, verified peer addresses, production-grade STARTTLS policy,
DNS trust operations, operational alerting, credential and signing-key
custody/rotation/revocation, durable nonces and replay prevention,
abuse resistance, rate limits, RFC5321/RFC5322/SMTPUTF8 handling,
monitoring, backup/recovery, delivery hardening and independent review.
Move these concerns through an explicit audited deployment decision.
Until then, the current Resend webhook remains only provider-event
origin evidence. Domain authentication is not human identity, authority
or payment safety.

**Production/TEST live app release: HARD HOLD.**
