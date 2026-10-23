# Android TEST secure session restoration — implementation contract

## Verified source behavior
The TEST web client in index.html stores Supabase access and refresh tokens in sessionStorage and restoreTestSession reads only sessionStorage. Cookie persistence in the Android WebView cannot restore these values after the WebView session is discarded. App.init invokes restoreTestSession and profile sync; temporary profile sync errors previously cleared the session (fixed on this isolated branch).

## Safe implementation direction
1. Keep existing browser sessions unchanged. For Android only, introduce an explicit native secure session store behind a trusted-origin bridge; do not place refresh tokens in localStorage, URL, logs, or plaintext SharedPreferences.
2. Bind the bridge to the exact TEST HTTPS origin and an authenticated session; use Android Keystore-backed authenticated encryption, account-scoped keys, and an explicit logout wipe. Do not enable addJavascriptInterface on arbitrary pages. Prefer origin-scoped WebMessageListener with verified source origin and no wildcard.
3. On startup, load the protected refresh credential, obtain a new access token from Supabase, validate currentAuthUser before opening authenticated UI, and preserve E2EE device keys separately in IndexedDB. Do not transfer Chrome keys automatically.
4. Handle invalid refresh token by clearing the stored credential and requiring login; transient network errors should not erase it.
5. Verify restart, rotation, logout, account switch, device revocation, offline restart, and two physical phones before release.

## Current gate
DESIGN ONLY. No native bridge, Keystore implementation, TEST deployment, or device acceptance tests yet. Production must not be modified.
