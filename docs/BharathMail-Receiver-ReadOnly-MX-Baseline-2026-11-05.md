# BharathMail receiver SPF pilot — non-mutating public DNS baseline

**5 November 2026 | Source-only audit; NO Cloudflare / registrar / Supabase action**

## Purpose
This scripted checkpoint inspects only the **public MX and NS records** of the existing \`bharathlink.com\` apex. It helps preserve evidence of the current mail-delivery topology before planning a genuinely separate test receiver. It does not alter records, send an email, infer SPF, inspect raw MIME, or authenticate an email. DNS observations can be stale or spoofed by upstream infrastructure; verify a real plan against authoritative zone configuration controlled by the owner.

Use: \`node scripts/bharatmail-public-mx-baseline-readonly.mjs\`. The source-only GitHub CI records the query results and 5 fail-closed tests.

**Do not enable Cloudflare Email Routing on this apex to run a test.** Cloudflare's official onboarding documentation states that routing can add MX, SPF and DKIM records to the root zone. That can conflict with the current Resend receiver. There is no connected Cloudflare account/zone management capability authorized in this ChatGPT session.

## Independent operator prerequisites (NOT yet done)
1. Authorized owner obtains a distinct test DNS zone (not the existing apex) and confirms unrelated current MX will not change. Record proof of zone control and a rollback plan.
2. Verify a controlled test sink and Cloudflare destination address without linking the staged default-reject worker to any live route.
3. Review actual first-party Cloudflare \`email()\` delivery and upstream \`Authentication-Results\` origin, anti-spoof ordering, SMTP connection IP, envelope sender, raw MIME integrity and recipient binding; no arbitrary copied headers.
4. Independently audit any receiver signing key custody, registry, revocation, replay and server-to-server attestation before enabling the staged gateway or database.
5. Separate SPF domain authentication from legal person identity, role authority and payment beneficiary verification.

Status: **SPF NOT CHECKED, trusted SMTP receiver NOT VERIFIED, sender/organization NOT VERIFIED, production/Android APK HOLD.**

Existing staged code is under \`mail-verifier/cloudflare-*\`, \`mail-verifier/verify-signed-smtp-receipt.mjs\`, and \`supabase/functions/bl-mail-auth-attest\`. Do not duplicate the credential or transport implementation.

See GitHub issues #10 (independent SMTP receiver) and #11 (identity issuer).
