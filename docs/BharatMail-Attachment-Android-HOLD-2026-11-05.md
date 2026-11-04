# BharathLink Mail — Attachment Preflight & Android External Security TEST Handoff

**Checkpoint:** 5 November 2026 (IST)
**Environment:** GitHub source-only, synthetic CI. **NO production / Android APK deployment.**
**Existing TEST:** user-confirmed DKIM + limited exact-domain DMARC PASS, local header/body/HTML caution checks. Real SPF and person/org authority still NOT VERIFIED.

## 1. Attachment preflight staged (not live)
- Source: `mail-verifier/attachment-preflight-offline.mjs`.
- Inspects, without opening or executing: declared filename, MIME type, byte length and initial magic bytes when supplied by a future trusted attachment pipeline.
- Detects suspicious executables, macro/active extensions, disguised/double-extension and bidi filenames, PDF/image magic mismatch, archive containers, unexpected/unknown file type, size mismatch and over-limit files.
- **No actual malware scanning, sandboxing, OCR, archive extraction, attachment download, HTML rendering, or safe-to-open assurance.** All verdicts are `not_scanned_for_malware`, with `allowed_to_preview=false`, `allowed_to_execute=false`, `allowed_to_download_automatically=false`, `attachment_safe=false`.
- Not wired to the existing TEST email page: this is only a reusable offline preflight for an eventual, approved attachment delivery pipeline. No attachment bytes or metadata were extracted from any real user mail.
- Ten adversarial tests: `mail-verifier/tests/attachment-preflight-offline.test.mjs`.
- GitHub CI [run 41892524171](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41892524171): **SUCCESS**. Verifier Node suite **144/144 PASS**; existing security regression suite **155/155 PASS**; receiver/Postgres and Edge/Wrangler jobs also successful.

## 2. Android TEST security-page handoff staged (not an APK)
- Sources: `BharathLink-Android/app/src/main/java/in/bharathlink/demo/MailSecurityLinkPolicy.java` and a source-only change to `MainActivity.java`.
- A user must explicitly tap `Mail Security TEST (external browser)` and confirm a disclaimer. It opens only the exact, pinned `https://oreadsachin400-dev.github.io/bharathlink-demo/bharatmail-dkim-test/` URL using Android `ACTION_VIEW` with a browsable category.
- The WebView remains configured to open the previous Netlify TEST app. No JavaScript bridge, JWT, email contents, cookies, keys, user UUIDs or payment data are passed through the native handoff.
- URL validation rejects scheme downgrade, host-suffix spoofing, username, custom port, query, fragment and changed path.
- Native source integration was **not** built against the Android SDK or run on a device. A Java 17 URL policy compile + adversarial test, and four static source HOLD tests PASS; these do not count as a complete Android instrumentation/build test.
- New GitHub CI [run 41892944680](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41892944680): **SUCCESS**, **SOURCE ONLY, NO APK**.
- The pre-existing APK GitHub build job still has `if: false`. No new APK artifact, signing action, install, Play Protect bypass, Netlify deploy or device enrollment.

## 3. Independent external blockers
- Real SPF requires a trusted receiving SMTP connection IP and MAIL FROM tied to original MIME and independently checked DNS; the current Resend webhook does not supply sufficient authenticated evidence. **SPF NOT CHECKED**.
- Sender/organization verification requires externally approved issuer/vetting authority, mailbox ownership, person-role binding, revocation, replay storage and security/privacy review; offline synthetic P-256 proofs do NOT authorize a Verified Sender badge.
- Android Play Protect disposition and original KeyPrep signing-key continuity still not confirmed. Existing production and TEST APK installation holds remain active.
- Attachment malware scanning requires a vetted server-side scanner with quarantined storage, file-type detection, zip-bomb limits and controlled access/download policy. Offline preflight is insufficient and not applied to live mail.
- Full DMARC organizational/PSD policy handling, two-physical-phone E2EE and independent security testing remain pending.

## Release decision
**HOLD.** Neither this source change nor tests authorize a live receiver, sender-verified claim, Android APK, attachment download, automatic message safety judgment, bank/authority approval or production launch. The existing TEST site and DKIM/DMARC backend are preserved.

## 4. Native WebView external URL policy hardening — source/compile verified
- The earlier source-only URL handoff itself passed 4 source tests but had not compiled the full Android Activity. That gap has now been closed.
- Added `ExternalNavigationPolicy.java` and wired it into `MainActivity.java`: only HTTPS external navigation from a **foreground main-frame user gesture** can open a browsable Android external intent. Blocked schemes include `intent:`, `file:`, `javascript:`, `content:`, `data:`, `http:`, `mailto:` and `tel:`. No external URL userinfo, custom ports, credentials fragments, or implicit iframe-driven launches are allowed.
- Same-origin `https://bharathlink-20-test.netlify.app/` remains in WebView, including normal internal query/hash routes. Host-suffix spoofing cannot become internal trust.
- This intentionally restricts generic external navigation (including mailto/tel) in the **staged source**. Compatibility of non-HTTPS external actions must be reviewed separately before any actual APK; do not loosen the gate casually.
- Updated GitHub Actions to `actions/setup-java@v5` and `actions/setup-node@v5`; added Java 17 compile against real Android SDK API 35 `android.jar` for `MainActivity.java`, `MailSecurityLinkPolicy.java` and `ExternalNavigationPolicy.java`. No Gradle assemble/sign/packaging or APK artifact was executed.
- **Final GitHub CI [run 41894318598](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41894318598): SUCCESS.** Java adversarial URL tests, Android SDK stub-source compilation, and all five static release HOLD tests passed.
- Remaining nonfatal toolchain notes (e.g. Java deprecated Activity API and transitive Node punycode) do not authorize a release or constitute a physical device test.
- All original Play Protect/signing-key clearance, first-device trust, independent external issuer, SPF receiver, E2EE and production gate requirements remain **HOLD**.
