# BharatMail TEST v6 — Company domain reference cautions, NOT identity verification

Date reviewed: 5 November 2026. Scope: **publicly documented examples only**, maintained as static data in `bharatmail-dkim-test/trust-engine.js`. Code is local and cannot fetch live registry updates. No changes to Supabase, Resend, DNS, email routing, mobile APK, or production.

## Documented domain references

- ICICI Bank: `icici.bank.in` is listed in its customer care page; its official contact page also references customer care on `icicibank.com` as a previous address. Official sources:
  - https://www.icici.bank.in/customer-care
  - https://www.icici.bank.in/contact-us
- Reliance Industries: its corporate fraud and recruitment-alert pages document `@ril.com` as an official company email suffix, and explicitly warn about unauthorized `@ril.vc`, `@ril.sg` lookalikes. Corporate and group/subsidiary email scopes can differ. Sources:
  - https://www.ril.com/fraud-alert
  - https://www.ril.com/careers/search-apply/fraud-alert

**These public website references are NOT an authoritative dynamic allowlist for all possible departments, employees, suppliers, partners, or subsidiaries.** Registry updates need human source review, organization approval, and signature-backed governance before a production-trust role.

## Detection and UI contract

- Exact full sender domain equality to one reviewed record → `published_domain_reference`, with published record kind/date. **Never Verified Sender**.
- Unlisted subdomain under a reviewed domain → `unlisted_subdomain` (no implicit inheritance of employee authorization).
- Close spelling, misleading brand-prefixed domain, or a company name claim with an unrelated domain → **caution only**; `ORG_REFERENCE_MISMATCH` / `ORG_REFERENCE_UNLISTED_SUBDOMAIN`. A mismatch is NOT proof of fraud.
- Unknown/unrelated domain → `not_listed`, not a fraud verdict.
- Fields explicitly separate `domainAuthentication: not_checked`, `organizationVerification: not_verified`, `senderMailboxAuthorization: not_verified`, `individualRoleAuthorization: not_verified`, `paymentBeneficiaryVerification: not_verified`.
- Existing independent DKIM/limited DMARC diagnostic (separate server endpoint) remains unchanged. This public-domain reference does not consume DKIM/SPF/DMARC data, grant mailbox ownership, or make payment requests safe.
- Existing content scanner and explicit local redacted report remain RLS-protected; reports contain only approved warning codes, not sender, body or links.

## Example interpretations

| From address example | Local reference result |
|---|---|
| `customer.care@icici.bank.in` | ICICI published reference **only; actual email NOT authenticated** |
| `help@icic.com` claiming ICICI | Possible lookalike / not in reference (not automatically fraud) |
| `alerts@bank.icici.bank.in` | Unlisted subdomain; may be legitimate but no authorization inferred |
| `jobs@ril.com` | Reliance Industries published reference **only; actual email NOT authenticated** |
| `recruitment@ril.vc` claiming Reliance | Published fraud-alert example; local caution does not establish live fraud |
| `jobs@reliance-support.com` | Unlisted brand-claiming domain, caution only |

## Production HOLD / third-party dependencies

Before any user-facing **Organization Verified**, **Verified Sender**, **Authorized Employee**, or **Verified Payment Beneficiary** label: independently authenticate the exact message, align SPF/DKIM/DMARC with trusted receiver evidence, verify current domain control and mailbox authorization with the organization, verify legal entity and role authorization through a genuine issuer, handle expiry/revocation and audit, and obtain independent security approval.

Resend `bharathlink.com` domain claim support case remains pending. Do NOT press `Start over` or change apex MX or mail routing. Android APK and production launch remain HOLD.

See existing GitHub issues #10 and #11.
