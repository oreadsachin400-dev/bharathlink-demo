# BharathLink — Phase 2 Account-to-Key Binding Gate
**2 November 2026 | TEST staging only | no mobile release**

## Grounded current evidence
- Physical Android standalone AUTH PROBE verified email OTP and returned `SUPABASE_TEST_EMAIL_AUTHENTICATED_ONLY` with a server-provided account UUID. This confirms TEST email authentication, not local key possession.
- Existing KeyPrep ONLY P-256 keys reside in a **different Android app package**. The separate AUTH PROBE cannot read those private keys.
- Previously manually entered KeyPrep account UUID label and newly authenticated account UUID were **different** in the user-provided test screenshots. Exact values are intentionally omitted from public source control.
- The original private APK signing key of the installed KeyPrep app has not been recovered/verified. A mismatched-signature update or uninstall may destroy access to non-exportable AndroidKeyStore keys.
- GoDaddy/Resend domain verified and Supabase SMTP / email template saved; physical OTP authentication passed. Existing DEMO and production untouched.

## Changes in this branch
- A new pure Kotlin `LocalBindingGate` explicitly distinguishes missing/expired session, mismatched account label, invalid key state, and local candidate match.
- `NativeAuthBindActivity` now uses the explicit gate after authenticated online `/auth/v1/user`, and does **not** silently substitute an unverified UUID label or approve a device.
- Negative JUnit cases reject mismatched accounts, expired sessions, missing device IDs, wrong key curves and malicious state strings.
- The phase-2 CI workflow compiles and unit-tests the same-package staged Android code. It **does not publish an APK**.
- No Supabase, production, DEMO, protected signing environments, user data, server-side approval, or enrolled devices are mutated by this commit.

## Security boundaries
1. **Never** uninstall, update, clear data, or regenerate existing KeyPrep keys to force a match.
2. Login alone is not evidence of identity/KYC authority or trusted device approval.
3. A local positive key match does not confer E2EE v2 readiness, approved signing key status, or enrollment.
4. A real native in-place update remains blocked pending recovered compatible signing identity and independent on-device installed-certificate verification.
5. If the signing key is irretrievable, a separately authorized fresh-device bootstrap would require new keys, fresh identity proof, and **no trust inheritance**. It is NOT performed here.
6. Candidate possession and device approval server RPCs remain gated and cannot be turned on by client changes.

## Acceptance / next gate
- GitHub Actions JUnit + Kotlin compile must pass on this branch.
- No user APK installation action follows from green CI.
- Only proceed to physical same-package key binding when genuine installed signing continuity and authenticated account/key label agreement can be independently established.
- Do not upload OTPs, keys, recovered keystores, or secrets in GitHub or chat.
