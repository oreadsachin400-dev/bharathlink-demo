# Android-to-V38 integration audit — source verified 2026-10-22

Source: `oreadsachin400-dev/BharathLink-Android-Demo` at `main`, read-only. This audit does NOT change Android source.

## Observed
- `app/src/main/java/in/bharathlink/demo/MainActivity.java` is a WebView wrapper loading `https://bharathlink-20-test.netlify.app/?bl_android_login=20261019b#/test-login`.
- It provides trusted-origin media permission mediation and a Chrome-login escape path.
- No native candidate-device enrollment, trusted-device approval, signature creation, or account recovery flow exists in this MainActivity.
- `app/build.gradle`: applicationId `in.bharathlink.testaudio.v7`, version `0.7-audio-diagnostic-test`, targetSdk 35.
- `AndroidManifest.xml`: INTERNET, RECORD_AUDIO, CAMERA. No visible push receiver/service in this manifest.
- Browser session and local E2EE keys are intentionally not copied into the isolated WebView.

## Verified backend gap
TEST `public.register_e2ee_v2_device(uuid,text,text)` authenticates with `auth.uid()`, validates canonical public-key encoding, and inserts a V2 device, but does not verify a signed approval from an already trusted device. Direct authenticated INSERT to `public.e2ee_v2_devices` is not granted; separate `public.messaging_devices` INSERT policy needs its own review.

## Implementation boundary
1. Inspect the actual deployed TEST web application's device-key creation and enrollment callers; Android wrapper alone cannot prove their behavior.
2. Identify the signing algorithm for V2 signing keys: TEST SQL accepts 32- or 65-byte encoded signing keys; V38 reference verifier uses P-256 JWK/P1363. Algorithm/encoding mismatch MUST block deployment.
3. Design two-device approval with explicit candidate key fingerprint, pending nonce, expiry, approver trust anchor, signature, and server-side transaction.
4. Preserve safe first-device bootstrap and recovery; do not silently create a trusted device from OTP alone.
5. Implement an authenticated server endpoint and transactional SQL migration in an isolated disposable environment; verify all alternative device-writer paths.
6. Test fresh Android WebView install, session restart, key persistence, two-phone approval, rejection, replay, revocation, and lost-device recovery before one TEST deploy.
7. Do not merge or deploy the isolated V38 reference directly; do not change production.

Status: DESIGN/COMPATIBILITY BLOCKED, not Android integrated, not APK ready.
