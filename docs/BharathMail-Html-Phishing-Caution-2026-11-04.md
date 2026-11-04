# BharathLink Mail — HTML Link Impersonation / Bounded Content Caution (SOURCE ONLY, HOLD)

**4 November 2026** | Branch: `bharathlink-mail-html-link-spoofing-caution-ci`

## Why this change is necessary

The already implemented `BharatMailTrustEngine.inspect()` inspected the external From address, the plain-text body and direct `http(s)://` links. However, existing external inbox sync also provides `html_body`. A scammer could include a harmless plain text alternative and put a deceptive clickable anchor in the HTML alternative, for example:

```html
<a href="https://evil.example/collect">https://bank.example/login</a>
```

The earlier trust-engine code did not inspect that HTML anchor's true `href`. This change improves local **caution signals** without treating any heuristics as independently verified sender authenticity.

## Implementation

`bharatmail-trust-engine.js` now:
- Inspects `html_body` for up to 16 ordinary anchor `href` targets under a bounded 48-KB sample, with no HTML execution, DOM insertion, remote lookup, external telemetry or link following.
- Warns `HTML_LINK_DESTINATION_MISMATCH` when a displayed full web URL has a different actual link hostname.
- Warns on URL shorteners, insecure HTTP, encoded URL punctuation, URL userinfo, raw IP destinations, punycode and unsafe/non-web link schemes in HTML anchors.
- Applies the local credential / urgency / payment request heuristics to text from the HTML alternative as well as the plain-text body; hidden scam language in an HTML-only email is not silently omitted.
- Samples the head and tail of oversized plain text / HTML; explicitly displays `INCOMPLETE_TEXT_SCAN` or `INCOMPLETE_HTML_SCAN` if it could not assess all content. HTML parsing is intentionally limited; complex markup is treated as unreviewed instead of complete.
- Does not falsely warn on normal `mailto:`, `tel:` or fragment (`#`) anchors.
- Sorts local reason labels by severity before the eight-item UI cap so that high-priority disguised-link warnings cannot be buried behind medium/info labels.
- Preserves `isVerified:false`, `isFakeProven:false`, `domainAuthentication:not_checked` for external mail and independent human/authority/payment verification as not verified.

The current `index.html` already passes `html_body` in external message objects through `BharatMailTrustEngine.inspect(m)`, so no deployment or UI source change was required to prepare the staged logic. The user-visible feature remains **source-only on a protected TEST branch**, not deployed to Netlify or an Android APK.

## Tests

`tests/bharatmail-trust-engine.test.mjs` adds 12 browser-independent Node tests that exercise spoofed anchor display vs destination, HTML-only shortened and masked URLs, encoded protocols, dangerous schemes, HTML alternative OTP/payment instructions, oversized body and HTML tail, malformed anchors, ordinary mailto/tel/fragment links, spoofed authentication headers, and warning priority.

The existing Mail Trust/security suite, signed SMTP evidence simulator, replay/rotation ledger and disposable PostgreSQL integration remain tested as part of the branch's GitHub workflow.

**Current CI verification:** [GitHub Actions — HTML Link Spoofing Caution CI](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/workflows/bharatmail-html-link-spoofing-caution-ci.yml). Final run link and passed counts are recorded in `docs/security-release-readiness.json` after completion.

## Important limitations

- This is an explainable **risk heuristic**, not proof of fraud. Legitimate email may link to a different domain for tracking/CDNs and malicious email may avoid every listed pattern.
- The HTML scan is a conservative bounded token inspection, **not** a complete RFC MIME or HTML5 parser or link sandbox. It never promises to analyze every HTML construct.
- There is **no live independent SPF/DKIM/DMARC evaluation** of customer mail, no real sender identity verification, no approved public SMTP receiving gateway, no trusted payments authority and no live phishing-url reputation lookup.
- An incoming Resend webhook establishes provider event provenance, not the third-party author's identity. Message-controlled `Authentication-Results` values are ignored for identity verification.
- Existing `MAIL_AUTH_RELEASED=false`, Play Protect, signer continuity, real identity-issuer and first-device approval gates remain **HARD HOLD**.

**Release decision: NOT DEPLOYED. No live Supabase, Resend, Netlify, DNS, website or Android APK changes.**
