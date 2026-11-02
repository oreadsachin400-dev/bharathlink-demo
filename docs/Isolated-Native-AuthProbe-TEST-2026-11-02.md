# BharathLink — Isolated Native Auth Probe v1
**2 November 2026 | Disposable Android TEST-only application**

## Reason for separate package
The installed `BharathLink KeyPrep ONLY TEST` app holds non-exportable AndroidKeyStore P-256 keys and was signed by an ephemeral CI signing key; the original signing private key is not currently available. Do NOT uninstall, update, rename, clear data, or try to copy keys to another package.

**Safe limited objective:** test email OTP authentication and `/auth/v1/user` account identity in a **stateless side-by-side Android app** without affecting any prior local keys.

## Package isolation
- New package: `com.bharathlink.app.test.authprobe` versionCode 1.
- Existing KeyPrep package: `com.bharathlink.app.test.keypreponly` versionCode 40.
- Dedicated single native launcher: `BharathLink Auth Probe TEST`.
- Permissions: Internet only. No SMS read, contacts, phone, camera, file access or Keystore operations.
- `allowBackup=false`, `usesCleartextTraffic=false`, `FLAG_SECURE` to reduce OTP screenshot exposure.
- This disposable app uses CI debug signing, so **do not use it to generate long-lived keys or expect in-place upgrade compatibility**. No local keys or persistent tokens are created by the probe.

## Auth flow
1. User manually enters an existing Supabase TEST email address and taps **SEND EMAIL OTP — TEST**.
2. Native client calls the Supabase TEST `/auth/v1/otp` with `create_user=false` and a publishable (not service-role) API key.
3. User enters the numeric email OTP **only in the installed probe**. Never paste/share OTP into chat, screenshots, GitHub or logs.
4. Client calls `/auth/v1/verify`, then authenticated `/auth/v1/user`, and checks server-returned user UUID, same email, confirmed address and non-anonymous status.
5. JWT is ephemeral and invalidated immediately after reporting result; no refresh-token persistence, local account binding or trusted-device registration.
6. Result is strictly `SUPABASE_TEST_EMAIL_AUTHENTICATED_ONLY` or generic fail-closed error. No KeyPrep/Keystore match is possible between packages.

## TEST environment constraints
- Supabase project: `BharathLink-20-TEST` / `fsdusofbpwdrdvgexxyw` only.
- Hosted email template actual content remains **UNVERIFIED**: email OTP requires `{{ .Token }}` in the existing Magic Link template. If project currently sends link only, the numeric OTP screen will not complete.
- No OTP messages sent automatically, no Auth configuration or users modified by this development.
- Back-end `bl20-candidate-possession` and trusted approval endpoints remain hard-disabled.

## Validation and evidence
- GitHub workflow `.github/workflows/build-isolated-auth-probe-test.yml` checks source ZIP SHA, unique app ID, single native launcher, no old KeyPrep class, no trust writes, Kotlin/JUnit tests, APK signer metadata and SHA-256. Build outcome must be verified in GitHub Actions.
- **Physical Android verification not yet performed.** CI compilation, even if green, is not proof that the OTP template sends numeric codes.
- No server enrollment, identity proof, key migration, approved trust or E2EE status is to be inferred from this test.

## Owner-friendly test once signed artifact is available
1. Leave all installed BharathLink apps unchanged. Install the separate `BharathLink Auth Probe TEST` APK as another app.
2. Open the one launcher named **BharathLink Auth Probe TEST**.
3. Use only an existing TEST email address; send a code at most once. Read the email inbox.
4. If the email contains a **numeric OTP**, enter that OTP within the app. Do not share it with ChatGPT.
5. Report only the resulting status label, not the email, code, access token or screenshots of the OTP field.
6. If the email includes only a link, stop and report **LINK_ONLY**. Do not alter hosted template or click unfamiliar redirects without review.

**Future milestones:** (a) independent phone-installed signing continuity or a newly authorized separate-package bootstrap, (b) verified first-device identity proof, (c) approved device enrollment, then (d) two-phone E2EE-v2 exchange. The probe does not accomplish these.
