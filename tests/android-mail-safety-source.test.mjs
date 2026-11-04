import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const webview=readFileSync(new URL('../BharathLink-Android/app/src/main/java/in/bharathlink/demo/MainActivity.java',import.meta.url),'utf8');
const policy=readFileSync(new URL('../BharathLink-Android/app/src/main/java/in/bharathlink/demo/MailSecurityLinkPolicy.java',import.meta.url),'utf8');
const workflow=readFileSync(new URL('../.github/workflows/build-android-test.yml',import.meta.url),'utf8');
const readiness=JSON.parse(readFileSync(new URL('../docs/security-release-readiness.json',import.meta.url),'utf8'));
test('user-initiated explicit external browser only, no implicit token forwarding',()=>{
 assert.match(webview,/mailSecurity\.setOnClickListener\(v->new AlertDialog\.Builder/);
 assert.match(webview,/\.setTitle\("Mail Security TEST only"\)/);
 assert.match(webview,/\.setPositiveButton\("Open TEST"/);
 assert.match(webview,/MailSecurityLinkPolicy\.isExactAllowedTestUrl\(MailSecurityLinkPolicy\.TEST_URL\)/);
 assert.match(webview,/new Intent\(Intent\.ACTION_VIEW,Uri\.parse\(MailSecurityLinkPolicy\.TEST_URL\)\)/);
 assert.match(webview,/Intent\.CATEGORY_BROWSABLE/);
 assert.doesNotMatch(webview,/addJavascriptInterface|evaluateJavascript|postWebMessage|setJavaScriptCanOpenWindowsAutomatically\(true\)/);
 assert.doesNotMatch(webview,/putExtra|Authorization.*Bearer|access_token|refresh_token|user_id|SupabaseClient/);
});
test('TEST endpoint is an exact HTTPS path, no deep links, no credentials or identity promotion',()=>{
 assert.match(policy,/"https:\/\/oreadsachin400-dev\.github\.io\/bharathlink-demo\/bharatmail-dkim-test\/"/);
 assert.match(policy,/TEST_URL\.equals\(input\)/);
 assert.match(policy,/url\.getRawUserInfo\(\) == null/);
 assert.match(policy,/url\.getRawQuery\(\) == null/);
 assert.match(policy,/url\.getRawFragment\(\) == null/);
 assert.match(webview,/No account, device, sender, organization or payment is verified by opening it/);
});
test('current WebView HTTPS boundary and no file/content access remain unchanged',()=>{
 assert.match(webview,/s\.setAllowFileAccess\(false\)/);
 assert.match(webview,/s\.setAllowContentAccess\(false\)/);
 assert.match(webview,/WebSettings\.MIXED_CONTENT_NEVER_ALLOW/);
 assert.match(webview,/https:\/\/bharathlink-20-test\.netlify\.app/);
 assert.match(webview,/web\.loadUrl\(HOME\)/);
 assert.match(webview,/web\.restoreState\(state\)/);
});
test('APK release remains disabled pending independent clearance',()=>{
 assert.match(workflow,/if: false/);
 assert.equal(readiness.release_decision,'HOLD');
 assert.equal(readiness.is_production_authorized,false);
 assert.equal(readiness.is_test_apk_install_approved,false);
 assert.equal(readiness.policy.no_apk_artifact_or_install,true);
 assert.equal(readiness.policy.no_deployment_from_this_branch,true);
});
