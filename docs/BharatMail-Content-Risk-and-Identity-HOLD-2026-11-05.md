# BharathLink Mail — Content Risk + Sender Authorization Handover
**Date:** 5 November 2026 (IST) · **Scope:** TEST only · **Production:** HOLD

## Tested live mailbox milestone
The existing user-owned Gmail reply previously passed **strict aligned DKIM** plus **exact-author-domain DMARC (DKIM-based)** on isolated Supabase TEST Edge v10. This does not establish SPF, personal sender identity, organizational affiliation, a safe payment beneficiary, or fraud detection.

## New public TEST site capability
On `main` at `bharatmail-dkim-test/`:
- `trust-engine.js` is a copy of the existing local-only, bounded caution engine; it does not call a web service or execute HTML.
- The authenticated mailbox page offers **Scan stored text & HTML links (locally)** per received message. User explicitly taps before loading content.
- The request uses the **signed-in user's JWT and existing owner RLS** on `public.bharatmail_external_messages`, bounded to that incoming message ID. It is not a service-role read.
- Browser-inspected sender, subject, stored body and HTML links are used for heuristic cautions: lookalike domains, public-webmail authority claims, OTP/secret requests, urgent payment requests, suspicious links, and visible-link/href mismatch.
- No raw mail body is displayed, logged, persisted, sent to a third-party AI, followed or executed. Attachments **never** scanned.
- No result is a Verified Sender badge, fraud proof, safety rating, payment approval or organizational identity proof.
- **CSP inline hash + external SRI pinned and checked.**
- Node synthetic TEST CI: **9/9 PASS** on [run 41890865494](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41890865494).
- GitHub Pages publication: **SUCCESS** on [run 41890864905](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41890864905).
- **Authenticated browser execution on actual stored body is still pending user-side one-tap test.** Offline CI/Pages success does not establish end-to-end runtime success.

## New source-only identity-authorization proof contract
On branch `bharathlink-mail-resend-live-dkim-readonly`:
- `mail-verifier/sender-identity-authorization-offline.mjs`: P-256 signed sender-person-to-organization authorization proof with exact email/domain binding, fixed schema and audience, key pinning, short expiry, fresh independent revocation callback and atomic replay callback requirements.
- The contract is strictly **OFFLINE SYNTHETIC**. A cryptographically valid synthetic receipt returns **identity/organization/mailbox ownership NOT VERIFIED**, `verified_sender_badge=false`, `production_release_authorized=false`.
- Not connected to a real issuer. No independent identity registration, legal-entity authority, person-to-role proof, credential custody, consent, revocation operator or durable nonce store was activated.
- 10 new adversarial tests cover signature substitution, forged properties, wrong user/org/mailbox, malformed domain, expiry, revocation, nonce replay and fail-closed status.
- [CI 41891448628](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41891448628): all 4 jobs SUCCESS. Mail verifier Node tests **134/134 PASS**, existing security regression Node tests **155/155 PASS**, plus receiver/postgres/Edge/Wrangler checks; no skipped Node tests.

## Trusted SMTP SPF blocking dependency
The live Resend webhook is not a trusted independent source of the actual connecting SMTP peer IP plus envelope MAIL FROM. Offline signed receiver and SPF/DMARC tests exist, but no reviewed live SMTP receiver / attested connection evidence is installed:
- `public.bharatmail_sender_auth_v1` absent in live TEST.
- `public.bl_mail_record_auth_attestation_v1` absent in live TEST.
- `bl-mail-auth-attest` Edge function absent in live TEST.

**Never derive SPF from attacker-supplied Received/Return-Path/Authentication-Results headers or assume SPF from successful DKIM/DMARC.** Keep `SPF: NOT CHECKED`.

## Remaining
- One owner-authenticated browser button test of local content scan.
- Independently approved operator-level SMTP evidence before enabling live SPF.
- Independently verified issuer, person/org role authorization, mailbox ownership, revocation/replay infrastructure, security review and regulations before any sender identity badge.
- Full DMARC organizational/public suffix discovery and policy tests before claiming generic DMARC certification.
- Production HOLD, original Android and unrelated device/security release gates unchanged.
