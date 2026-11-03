# BharathLink Phase 7A — Native TEST authenticated account-to-key matching
3 November 2026 | Separate package, never an in-place KeyPrep update

## Latest verified baseline
Phase 6 isolated Fresh KeyPrep Android app was installed and launched on a real Android phone. Disposable P-256 signing and ECDH keys were generated. Local signing verification, tampered-signature rejection, ECDH agreement, and post-relaunch key presence passed in the supplied screenshots. No server challenge, trust or real two-phone E2EE was tested.

## What Phase 7A implements
- New, separate `com.bharathlink.app.test.phase7bind` package and AndroidKeyStore aliases. Original KeyPrep and Phase 6 remain untouched. There is NO key migration.
- Native email OTP flow strictly against Supabase **BharathLink-20-TEST**, using existing publishable key only. Existing account required (`create_user=false`); OTP is masked and not retained. Verified user UUID is taken from `/auth/v1/verify` and rechecked using online `/auth/v1/user`, never a typed UUID.
- Only when a live, foreground OTP session is valid: self-test fresh local P-256 ECDSA signing, tamper rejection and ECDH agreement, then locally bind exact authenticated user UUID to disposable device UUID and SHA-256 public key fingerprints.
- Subsequent account mismatch, changed keys, partial stored bind and invalid session are fail-closed; no key deletion or silent reset.
- No service-role credentials; no public RPC to devices; no Supabase enrollment-table INSERT/UPDATE, independent identity proof, issuer trust or activation.
- Native program has only INTERNET permission. Network code allows HTTPS calls to `fsdusofbpwdrdvgexxyw.supabase.co` and `/auth/v1/{otp,verify,user}`. No WebView, JavaScript bridge, messaging or payment code.
- Automated tests check binding mismatch, key/fingerprint mismatches, malformed input, session expiry and existing authentication policy. Android CI checks resulting package ID, launcher, signing, and exact permission set.

## Security qualifications
- `LOCAL_ACCOUNT_KEY_MATCH_ONLY_NOT_TRUSTED` means a TEST Supabase email OTP subject was matched to keys generated INSIDE THIS TEST PACKAGE. It DOES NOT mean independent person identity verification, server-side key challenge, remote enrollment, approved device, or E2EE-ready.
- A different package cannot reuse Phase 6 or original KeyPrep private keys. The GitHub Actions debug signature may vary between runs; do not rely on this build for durable enrollment state or update it over old KeyPrep.
- Existing `bl20-candidate-possession` and `bl20-device-approval` functionality is not enabled by this phase. Live device approval and first-device independent bootstrap remain blocked.
- Supabase-20-TEST database/schema/edge functions were inspected READ ONLY. No migrations, permission changes, toggles, RLS changes or deployments were performed.
- Before test installation confirm the GitHub Phase 7A workflow is green and APK manifest audits pass. Keep the Phase 6 and original KeyPrep apps installed.

## Physical test procedure — once CI succeeds
1. Install the separate Phase 7A TEST APK *alongside* original KeyPrep and Phase 6; never uninstall them.
2. Press **Create disposable P-256 keys** one time.
3. Enter an existing Supabase TEST account email; request numeric OTP and verify inside the new test app. Do not share the OTP.
4. Expected: `LOCAL_ACCOUNT_KEY_MATCH_ONLY_NOT_TRUSTED` with TEST account UUID and both public fingerprints; serverApproved=false, trustedDevice=false, e2eeV2Ready=false.
5. Close/relaunch and press **Check local status**. The same bound UUID and fingerprints must persist.
6. Attempting to bind a *different* TEST account must be rejected; do not reset or regenerate keys.
7. Do not interpret results as independent identity proof or a second-phone E2EE test.

## Phase 7B / follow-on blockers
A real server-generated one-time challenge with verified signed possession, rigorous replay-safe receipt consumption, verified independent first-device bootstrap, stable APK signing, explicitly authorized activation and finally two-phone E2EE verification are separate future gates. Never unblock trust by merely changing a frontend boolean or disabling existing hard gates.

## Branch
`bharathlink-phase7a-isolated-auth-keybinding-test`
Workflow: `.github/workflows/phase7a-isolated-auth-binding-android.yml`.

## Physical Android installation blocker — 3 November 2026
The user attempted to install the CI-generated Phase 7A TEST APK on Android. Google Play Protect displayed **Harmful app blocked: This app can put your device or data at risk**. The installation was blocked. No physical OTP account-key binding test is claimed or permitted based on the current result. Preserve the APK for forensic review but do NOT direct the user to disable Play Protect, bypass its classification, or force install.

Artifact independently reviewed offline: GitHub CI ZIP and extracted APK SHA-256 **a16768f0ee8519ecd144ac032c54d32a3735aa6a09577d3f4fc080be77e6cd7e** match, zip structure is intact, the APK is debug signed (certificate CN=Android Debug) and declares INTERNET only. These checks DO NOT establish malware safety, explain Google's classification, or override the warning.

Next safe step: Capture the Play Protect **More details** classification without proceeding with installation; inspect source and bundled dependencies against the category Google reports, review Android security/permissions and signing/distribution. If analysis supports a false-positive determination, use Google's Play Protect developer appeal process. Keep phone test **BLOCKED** until issue is resolved. Phase 6 PASS remains unchanged. Existing KeyPrep, DEMO, TEST Supabase data and device trust flags stay untouched.

Google developer guidance: https://developers.google.com/android/play-protect/warning-dev-guidance
