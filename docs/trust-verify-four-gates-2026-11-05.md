# BharathLink Trust Verify — isolated TEST implementation
Date: 2026-11-05 | Status: read-only feature branch, SECURITY HOLD unchanged

## What is implemented
- A home entry **Trust Verify** and a separate /trust-verify view.
- A read-only exact Indian phone-number check against the existing authenticated Supabase **search_verified_directory** RPC in the BharathLink Demo project.
- A four-gate assessment: WHO, SAME WHO, WHERE, AUTHORITY.
- The WHO gate can say **official directory endpoint listed**, but never **caller authenticated**, only when the result belongs to exactly one entity, has verified status, exact matching number, valid verification timestamp, no expired claim, and exact endpoint match type.
- The other three gates remain explicitly **NOT ESTABLISHED**. The overall decision remains **HOLD** even if WHO has a directory endpoint match.
- Search errors, unauthenticated state, no match, a stale claim, ambiguous entity matches and unexpected endpoint types fail closed.
- No new table, RLS, mail route, payment write, E2EE operation, external AI API or production Netlify deploy.
- Automated tests cover exact matching, stale/pending claims, multiple owners, missing evidence, no-match language, nonpayment, code syntax, and route wiring.

## Why this is honest trust verification
Finding a verified bank phone in a directory does *not* prove that the current audio call is from the bank: caller ID may be spoofed. Likewise a verified logo, sender email, website, public key, or KYC profile is not proof of this payment request. A no-match result does not imply a scam.

| Gate | Working in this TEST branch | Evidence required to eventually pass |
| --- | --- | --- |
| WHO | Verified **official endpoint listing** only | Fresh authoritative directory claim plus live caller/device proof and controlled issuer |
| SAME WHO | NOT ESTABLISHED | Signed channel-binding to same verified subject across calling, messaging, and mail; replay protection |
| WHERE | NOT ESTABLISHED | Authorised UPI PSP/bank beneficiary ownership assertion for precise payee identifier, short TTL |
| AUTHORITY | NOT ESTABLISHED | Issuer-signed delegation containing role, department, scope, amount/currency, beneficiary, expiry, nonce, revocation |
| Overall safe to pay | HOLD | Independent proofs AND confirmation of amount, intended recipient and request with protected human approval; even then security is not guaranteed |

## Integration and release blockers
1. **Account isolation:** Current screenshot of BharathLink-20-TEST shows account data from the separate Demo Supabase project. Resolve environment mapping and the authentication/login design before attempting integration; this branch is attached to the **Demo repo only**, not the 20-TEST deployment.
2. **E2EE key availability:** Current TEST browser reports no local key; do not delete/re-enroll/rekey automatically. A read-only device assessment is safe; fresh-device approval and non-extractable key custody require independent proof.
3. **Trust sources:** There is no authenticated cross-channel binding, UPI PSP validation or request-delegation issuer enabled. Do not claim those gates verified.
4. **Review and tests:** The feature is not merged into main. A feature-branch CI test is committed but a green GitHub Actions run must be observed before merge. Real Android tests with both accounts are outstanding.
5. **Email/phone security:** Domain similarity and DKIM/SPF/DMARC can inform caution but not issuer authority or payment authorization. Treat lookalike domain matches as potential risks, never implicit verified identities.

## Safe next steps
- Keep this branch isolated until the login/E2EE security hold is resolved and the correct TEST source is identified.
- Add a trusted **signed issuer evidence contract** for SAME WHO, WHERE and AUTHORITY with key-pinning and expiry checks in a separate review branch.
- Integrate only into a non-production TEST build after code review and regression/Android tests; no forced logout or clearing of local encryption keys.

## Files
- index.html: read-only screen + pure four-gate evaluator + HOME route.
- tests/trust-verify-four-gates.test.mjs: regression tests.
- .github/workflows/trust-verify-four-gates-ci.yml: isolated CI.
