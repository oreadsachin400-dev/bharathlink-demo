#!/usr/bin/env python3
"""TEST-only WebView diagnostic applied after existing startup rescue patch."""
from pathlib import Path
root=Path("v36hf-kotlin-build")
activity=root/"app/src/main/java/com/bharathlink/app/MainActivity.kt"
gradle=root/"app/build.gradle.kts"
def one(path, old, new):
 s=path.read_text()
 assert s.count(old)==1, f"Expected one anchor, found {s.count(old)} in {path}"
 path.write_text(s.replace(old,new,1))
one(activity,'import android.view.MotionEvent\n','')
one(activity,'    private var startupUserInteracted = false\n','')
one(activity,'''    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            startupUserInteracted = true
            startupHandler.removeCallbacksAndMessages(null)
        }
        return super.dispatchTouchEvent(event)
    }

''','')
one(activity,'''    private fun offerStartupRecovery() {
        if (startupUserInteracted || startupRescueShown || isFinishing || isDestroyed) return
        startupRescueShown = true
''','''    private fun offerStartupRecovery() {
        if (startupRescueShown || isFinishing || isDestroyed) return
        if (pageLoaded) {
            webView.evaluateJavascript("""
                (function(){
                    const t = ((document.body && document.body.innerText) || '').trim();
                    const b = document.querySelectorAll('button,input,textarea,[role="button"]').length;
                    return t.length > 60 && b > 0 ? 'ready' : 'loading';
                })();
            """.trimIndent()) { result ->
                if (result?.contains("ready") != true) showStartupRecoveryDialog()
            }
            return
        }
        showStartupRecoveryDialog()
    }
    private fun showStartupRecoveryDialog() {
        if (startupRescueShown || isFinishing || isDestroyed) return
        startupRescueShown = true
''')
one(activity,'            userAgentString = "$userAgentString BharathLink-Android/36HF-TEST"\n',
    '            // Retain stock Android System WebView UA for TEST compatibility.\n')
one(activity,'    private var startupRescueShown = false\n',
'''    private var startupRescueShown = false
    private var jsErrorCount = 0
''')
one(activity,'''            .setMessage("If the application is still showing a loading spinner, retry the TEST site or try the other approved TEST host.")''',
'''            .setMessage("If the loading spinner is stuck, retry the TEST site or open it in your browser. " +
                "JavaScript error count: " + jsErrorCount)''')
one(activity,'''                webView.loadUrl(OriginPolicy.defaultPage)
            }
            .setNeutralButton("Try AI Studio TEST") { _, _ ->
                webView.loadUrl("https://ais-dev-rct6nb4sdglft27shfgdyd-143017817560.asia-southeast1.run.app")
            }''',
'''                startupRescueShown = false
                jsErrorCount = 0
                webView.loadUrl(OriginPolicy.defaultPage)
                startupHandler.postDelayed({ offerStartupRecovery() }, 30_000L)
            }
            .setNeutralButton("Open in Browser") { _, _ ->
                openExternalIfSafe(OriginPolicy.defaultPage)
            }''')
one(activity,'''        webView.webChromeClient = object : WebChromeClient() {
            override fun onPermissionRequest(request: PermissionRequest) {''',
'''        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(message: android.webkit.ConsoleMessage?): Boolean {
                if (message?.messageLevel() == android.webkit.ConsoleMessage.MessageLevel.ERROR) {
                    jsErrorCount++
                    Log.w(TAG, "Trusted TEST JavaScript error (content omitted)")
                }
                return true
            }
            override fun onPermissionRequest(request: PermissionRequest) {''')
one(activity,'''            override fun onPageFinished(view: WebView, url: String) {''',
'''            override fun onReceivedHttpError(
                view: WebView,
                request: WebResourceRequest,
                response: android.webkit.WebResourceResponse
            ) {
                if (request.isForMainFrame) {
                    Log.w(TAG, "Main-frame HTTP status " + response.statusCode)
                }
            }
            override fun onPageFinished(view: WebView, url: String) {''')
one(gradle,'versionCode = 37','versionCode = 38')
one(gradle,'versionName = "36.0.1-HF-STARTUP"','versionName = "36.0.2-HF-WEBVIEW-DIAG"')
s=activity.read_text()
assert 'dispatchTouchEvent' not in s and 'startupUserInteracted' not in s
assert 'addJavascriptInterface' not in s and 'getSecureToken' not in s
assert 'Open in Browser' in s
print("V36HF_WEBVIEW_DIAG_PASS; versionCode=38")
