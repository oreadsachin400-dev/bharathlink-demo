# BharathLink Mail — Real HTTPS Pilot Web Page Root-Cause and Recovery (4 Nov 2026)

## Status: server API ready, static TEST frontend not yet hosted

The original public link
`https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bharatmail-dkim-test-ui`
**was NOT a browser-ready webpage** despite the earlier 200 HTTP response.
A real GitHub Actions Internet-request smoke test showed the response
`Content-Type: text/plain`, which caused the browser to display HTML
source rather than execute it. Supabase deliberately rewrites HTML on
the default Edge Functions domain to text/plain.

Official documentation:
https://supabase.com/docs/guides/functions/http-methods
https://supabase.com/docs/guides/functions/limits

The incorrect UI URL has now been safely replaced with a **410 JSON notice**
(test Edge function version 2). The `bharatmail-dkim-check-test` backend
remains unchanged, `ACTIVE`, **verify_jwt=true**, and only accepts requests
from authenticated existing TEST users for owned inbound mail. The existing
Resend inbound webhook, DNS/MX, Supabase tables, original project, Netlify and
Android APK remain unchanged.

### Actual remote validation

[GitHub CI #41849734337](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41849734337)
**PASS**:
- Remote Supabase HTTPS responds with intentional 410 JSON notice rather than
  claiming a working HTML login page.
- Remote test-only DKIM API rejects POST without a user bearer (401/403).
- No user content, JWT, Resend token, or private email ID is used.
- This is NOT a real signed-in inbound email cryptographic result.

### Static test frontend packaged for operator deployment

A **separate static ZIP** was built in the active ChatGPT artifact container:
`BharathLink_Mail_DKIM_TEST_Site.zip`, containing `index.html`, `_headers`,
and `README_FIRST.txt`. The download itself is shared in ChatGPT, not
automatically uploaded to the public GitHub repository. Inline script and
style use SHA-256-based Content-Security-Policy; the Netlify `_headers`
adds frame-ancestors protection. No private key, Resend token, JWT or password
is included. Authentication happens from the browser directly to
`fsdusofbpwdrdvgexxyw.supabase.co`; JWT stays in page memory only.

**No static hosting access is connected in this session**. Do not claim
a Netlify deployment or a live static-site preview URL. The account owner
can upload this ZIP (or extract it and drop the folder, depending on the
Netlify Drop uploader) to a **new isolated TEST site only**. Netlify's own
manual deploy guide:
https://docs.netlify.com/deploy/create-deploys/

Once the static HTTPS TEST site is actually online, the user can sign in
to an existing BharathLink-20-TEST account (not the distinct original
BharathLink Demo project) and click **Check DKIM domain signature** on an
existing received email. No credentials should ever be pasted into chat.

The data store contains 6 inbound user-owned mail rows tied to 2 existing
TEST Auth users, but no such authenticated DKIM result has been observed.
The original TEST inbound-event authentication statuses remain unverified.

**Identity and release boundary:** A successful domain DKIM signature is
not personal identity, government/bank authority, SPF, DMARC, payment
beneficiary or safety. Production release remains HOLD.
