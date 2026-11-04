# BharathMail — Exact-Domain DMARC TEST v10 Handover
**4 November 2026 — isolated BharathLink-20-TEST only**

## Last independently confirmed live evidence
- A user-owned incoming Resend message ("Re: Isolation", received 04 Nov at 23:13 IST) returned **DKIM domain signature VALID** on the existing authenticated TEST UI.
- Supabase recorded a corresponding successful POST on 04 Nov at 18:17:44 UTC while the DKIM TEST endpoint was version 9.
- This is **NOT** evidence of SPF, DMARC, personal identity, organization authority or payment verification.
- The earlier fail-closed route-table permission problem was corrected using server-only minimum column SELECT; bearer credentials, raw MIME, and reply tokens were not exposed in the browser.

## Added in version 10
- `supabase/functions/bharatmail-dkim-check-test/dmarc-dkim-only.mjs`: exact RFC 5322 From-domain DMARC policy assessment (RFC 9989, May 2026).
- The module runs only **after strict, real original-MIME DKIM PASS**, with exact DKIM signing-domain alignment. It queries independently controlled DNS-over-HTTPS for `_dmarc.<author-domain>` TXT, validates a unique syntactically valid policy, then reports **domain-level DMARC PASS by DKIM**.
- The report is deliberately **limited** to an exact-domain DMARC record: it does **not** implement the RFC 9989 organizational/public-suffix tree walk. If no exact record is available or DNS fails, the result is **NOT CHECKED**, never FAIL or PASS guessed from headers.
- An observed `p=none` DMARC policy can still yield aligned-authentication PASS; it does not authorize a Verified Sender badge or enforcement decision.
- NO SMTP connecting-IP or MAIL FROM evidence is available from the current trusted Resend webhook; **SPF remains NOT CHECKED**. Neither a `Received` header nor client-supplied `Authentication-Results` qualifies as SPF evidence.
- No individual identity, legal authority, bank affiliation, payment account, company permission or safety of the request is asserted.
- Access remains JWT + owner-scoped RLS; no mailbox/database writes, MX/DNS changes, new receiver, Netlify app change, or main-project deploy.
- The exact-domain helper is copied byte-for-byte into the source-only offline test area, which includes invalid record, duplicate DNS policy, injected header, missing DNS, and no-SPF PASS-denial tests.
- Spoof warning regression tests demonstrate that even if domain-auth PASS occurs, lookalike/public-webmail authority claims and urgent payment language remain suspicious and do **not** grant identity.

## Verified status
- GitHub offline/security CI: PASS all jobs: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41886923702
- Isolated Supabase Edge `bharatmail-dkim-check-test`: **v10 ACTIVE**, `verify_jwt=true`; management read-back verified.
- Public GitHub Pages TEST UI updated to display separate SPF and limited DMARC results. The Pages deployment status must be independently checked before claiming browser publication.
- **No authenticated live DMARC-v10 request result confirmed yet**. The user-owned 04-Nov email can be checked again; do not require them to send a new email.
- Production release: **HOLD**. Existing security release gates must not be relaxed.

## Remaining gates
1. Confirm GitHub Pages publish of the updated TEST UI and run exactly one user-owned fresh v10 DMARC request on the existing received message. The assistant cannot supply the user's secret Auth JWT and must not request it.
2. Only an approved, independently authenticated receiver with true SMTP connection IP + envelope MAIL FROM and bound original MIME can authorize live SPF verification.
3. Full DMARC must implement RFC 9989 organizational-domain/PSD tree walk, policy conflict semantics, DNS error handling and PSL (public suffix) logic before a generic DMARC feature claim.
4. Sender/person/organization identity binding requires independent issuer/authorization and revocation evidence, plus explicit account ownership linkage; DKIM or DMARC alone is insufficient.
5. Spoof heuristics remain caution signals only, not fraud proofs or verified-safe classifications.

Standards: https://www.rfc-editor.org/rfc/rfc9989.html
