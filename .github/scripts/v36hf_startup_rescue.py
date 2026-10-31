#!/usr/bin/env python3
"""V36HF TEST-only startup hotfix. Runs on unpacked, checksum-verified source."""
from pathlib import Path

root = Path("v36hf-kotlin-build")
policy = root / "app/src/main/java/com/bharathlink/app/util/OriginPolicy.kt"
activity = root / "app/src/main/java/com/bharathlink/app/MainActivity.kt"
gradle = root / "app/build.gradle.kts"

def replace_once(path, old, new):
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly 1 anchor in {path}, got {count}: {old[:50]}")
    path.write_text(source.replace(old, new, 1))

replace_once(policy,
    'const val defaultPage = "https://ais-dev-rct6nb4sdglft27shfgdyd-143017817560.asia-southeast1.run.app"',
    'const val defaultPage = "https://bharathlink-20-test.netlify.app/"')
replace_once(gradle, 'versionCode = 36', 'versionCode = 37')
replace_once(gradle, 'versionName = "36.0.0-HF"', 'versionName = "36.0.1-HF-STARTUP"')
replace_once(activity, 'import android.os.Bundle\n',
    'import android.os.Bundle\nimport android.os.Handler\nimport android.os.Looper\nimport android.view.MotionEvent\nimport androidx.appcompat.app.AlertDialog\n')
replace_once(activity, '    private var pageLoaded = false\n',
'''    private var pageLoaded = false
    private val startupHandler = Handler(Looper.getMainLooper())
    private var startupUserInteracted = false
    private var startupRescueShown = false

    private fun offerStartupRecovery() {
        if (startupUserInteracted || startupRescueShown || isFinishing || isDestroyed) return
        startupRescueShown = true
        AlertDialog.Builder(this)
            .setTitle("BharathLink TEST is taking too long")
            .setMessage("If the application is still showing a loading spinner, retry the TEST site or try the other approved TEST host.")
            .setPositiveButton("Retry Netlify TEST") { _, _ ->
                webView.loadUrl(OriginPolicy.defaultPage)
            }
            .setNeutralButton("Try AI Studio TEST") { _, _ ->
                webView.loadUrl("https://ais-dev-rct6nb4sdglft27shfgdyd-143017817560.asia-southeast1.run.app")
            }
            .setNegativeButton("Dismiss", null)
            .show()
    }
''')
replace_once(activity, '        handleCallIntent(intent)\n        if (Build.VERSION.SDK_INT',
    '        handleCallIntent(intent)\n        startupHandler.postDelayed({ offerStartupRecovery() }, 30_000L)\n        if (Build.VERSION.SDK_INT')
replace_once(activity, '    override fun onDestroy() {\n',
'''    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            startupUserInteracted = true
            startupHandler.removeCallbacksAndMessages(null)
        }
        return super.dispatchTouchEvent(event)
    }

    override fun onDestroy() {
        startupHandler.removeCallbacksAndMessages(null)
''')
replace_once(activity, '''            override fun onPageFinished(view: WebView, url: String) {
''',
'''            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: android.webkit.WebResourceError
            ) {
                if (request.isForMainFrame) {
                    Log.e(TAG, "Main-page load failed; errorCode=${error.errorCode}; host=${request.url.host}")
                }
            }

            override fun onPageFinished(view: WebView, url: String) {
''')
assert "https://bharathlink-20-test.netlify.app/" in policy.read_text()
assert "getSecureToken" not in activity.read_text()
assert "addJavascriptInterface" not in activity.read_text()
assert "startupHandler.postDelayed" in activity.read_text()
assert "versionCode = 37" in gradle.read_text()
print("V36HF STARTUP RESCUE PATCH PASS: default Netlify TEST; explicit fallback; versionCode 37; no bridge privilege expansion")
