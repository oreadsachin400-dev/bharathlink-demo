# BharathLink — Native TEST Authenticated Account Binding v1
**2 November 2026 | Compile-only staging. Existing phone keys and app unchanged.**

## Why
The physical KeyPrep TEST app previously generated and retained P-256 signing and ECDH keys under its own Android application sandbox. The account UUID was only a manually entered label. Matching that label to an independently authenticated Supabase account is a separate step, distinct from trusted-device approval.

## Implemented in this branch
1. `NativeTestAuth.kt`: native HTTPS-only email OTP request `/auth/v1/otp` with `create_user=false`; OTP verification `/auth/v1/verify` and online `/auth/v1/user` cross-check. Account user ID comes only from the verified GoTrue user response. The user's manually typed UUID is **not** used as authentication.
2. `NativeAuthBindActivity.kt`: TEST UI for existing account email OTP; does **not** create local keys or call any trusted-device enrollment, E2EE, messaging or payment endpoints. It finds existing local keys under verified account UUID only.
3. `AuthBindingPolicy.kt`: verifies exact account UUID equality, existing device UUID, local KeyPrep state and P-256 signing/ECDH public-key presence. Fail closed on mismatches.
4. `EphemeralTestSession.kt`: JWT access token is foreground-only and expires, gets invalidated on background/sign-out. No refresh-token persistence, WebView sharing or credential logging.
5. `NativeAuthConfig.kt`: public-only Supabase TEST publishable API key, **never** service-role key.
6. `v36hf_native_auth_bind.py`: integrates additional non-exported auth activity into the same TEST application ID `com.bharathlink.app.test.keypreponly` for prospective secure **in-place update only**. Uses HTTPS, backup-disabled, no cleartext, one KeyPrep launcher. No extra launcher icon.
7. GitHub CI includes negative unit tests for wrong-account UUIDs, missing keys, wrong curves, expired and revoked in-memory sessions, alongside Kotlin compiler and existing tests.

## Verified before this phase
- Physical Android KeyPrep-only launcher, local signing/ECDH P-256 key generation and key persistence were already verified.
- Back-end TEST candidate proof and approval edges remain hard disabled.
- 8 pre-existing messaging devices, 0 enrollment requests, 0 candidate proofs, and 0 verified signer trust anchors at last TEST audit.

## Important release blockers
- **Signing-key continuity**: GitHub runner's ephemeral debug signing key may not match the certificate of the installed KeyPrep APK. Android requires the same package ID and signing identity to update without uninstall; uninstall would delete the previously tested keys. **Do not distribute the CI debug APK** or ask for uninstall. Secure stable signing is a prerequisite to a safe installed-app update.
- **OTP template configuration**: Existing Supabase TEST email template must send a numeric OTP (`{{ .Token }}`). If it currently sends only a magic link, the native OTP form cannot complete. This configuration has not been verified or changed.
- **Physical native auth**: No email OTP was sent by this work, and no live session-to-keystore binding has been exercised on the phone.
- **Independent bootstrap**: Login and local-key possession cannot substitute for separately verified first-device identity, trust approval or E2EE-v2 registration. Those remain OFF.
- The app source is compiled in GitHub CI; **no APK artifact is uploaded** by this native auth workflow.

## Next engineering sequence
1. Confirm an in-place update can be signed with the same existing KeyPrep signing certificate. If the original private signing key is unavailable, design and explicitly authorize a new key/bootstrap migration instead of silently deleting old keys.
2. Verify TEST email OTP template and complete real OTP + `/auth/v1/user` subject validation from the native app after safe signing.
3. Test matching/mismatching account on physical phone without regenerating existing keys, and test session invalidation after background/restart/sign-out.
4. Only then, independently validate first-device trust bootstrap, review risk controls and separately enable live *candidate possession* (not trust approval) for a bounded TEST rollout.
5. Follow with approved device enrollment and two physical phones' E2EE-v2 exchange.

**Security verdict: Native authenticated binding staged; NOT live enrolled, NOT trusted, NOT production-ready.**
