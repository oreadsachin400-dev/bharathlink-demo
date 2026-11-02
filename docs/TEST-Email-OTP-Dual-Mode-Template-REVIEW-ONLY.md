# BharathLink-20-TEST — Optional dual-mode Magic Link / Email OTP template

**NOT DEPLOYED.** Supabase-hosted email template settings could not be read through the connected project's available tools. This document is a review-only example.

Supabase email OTP and magic-link sign-in share the Magic Link email template. To avoid breaking existing TEST web login, **preserve `{{ .ConfirmationURL }}`** while adding a code for the native TEST flow.

## Proposed TEST-only template body (review before use)

```html
<h2>BharathLink TEST sign-in</h2>
<p>Use this one-time code to sign in to the BharathLink TEST app:</p>
<p><strong>{{ .Token }}</strong></p>
<p>Or use your existing TEST sign-in link:</p>
<p><a href="{{ .ConfirmationURL }}">Sign in to BharathLink TEST</a></p>
<p>If you did not request this sign-in, ignore this email.</p>
<p>This is a TEST account message. Never share your code.</p>
```

## Required safeguards

- Do not alter or deploy this template unless the actual current TEST template has been reviewed and approved. Preserve existing branding, subject, confirmation link and redirect behavior.
- Do not include `service_role` or private keys in the template.
- Never request that a user send the OTP to ChatGPT, GitHub, a test log or a developer.
- Avoid creating new accounts from `signInWithOtp`: native code must keep `create_user=false`.
- Review current SMTP service, delivery rate limits and email prefetched-link behavior.
- Before any physical TEST, verify the real template renders a numeric code and the existing web magic link continues working.
- Device enrollment and E2EE approval remain OFF regardless of email OTP success.

## Verification status

- Official Supabase documentation confirms `{{ .Token }}` is usable for email OTP while `{{ .ConfirmationURL }}` is available for magic links.
- **Existing hosted template contents: UNVERIFIED.**
- **Template deployment: NOT PERFORMED.**
- **Live OTP delivery/login: NOT TESTED.**

Dashboard owner route (when needed): Supabase TEST project → Authentication → Email Templates → Magic Link.

