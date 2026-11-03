#!/usr/bin/env python3
"""Build a completely separate Phase 7A TEST APK from pinned source scaffolding.

No original KeyPrep package update, no approved enrollment, no RLS mutation.
Only Android INTERNET permission for Supabase-20-TEST /auth/v1/* over HTTPS.
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root=Path("v36hf-kotlin-build")
main=root/"app/src/main"
assert main.is_dir()
for parent in (main,root/"app/src/test"):
    if parent.is_dir():
        for item in parent.rglob("*"):
            if item.is_file() and item.suffix in (".kt",".java"):
                item.unlink()

phase=main/"java/com/bharathlink/app/phase7"
phase.mkdir(parents=True,exist_ok=True)
for name in ("Phase7AuthBindActivity.kt","AccountKeyBindPolicy.kt"):
    copyfile(Path("android-phase7a")/name,phase/name)
auth=main/"java/com/bharathlink/app/keyprep"
auth.mkdir(parents=True,exist_ok=True)
for name in ("NativeTestAuth.kt","NativeAuthConfig.kt",
             "AuthBindingPolicy.kt","EphemeralTestSession.kt"):
    copyfile(Path("android-keyprep")/name,auth/name)

testroot=root/"app/src/test/java/com/bharathlink/app"
(t7:=testroot/"phase7").mkdir(parents=True,exist_ok=True)
copyfile(Path("android-phase7a/AccountKeyBindPolicyTest.kt"),
         t7/"AccountKeyBindPolicyTest.kt")
(ta:=testroot/"keyprep").mkdir(parents=True,exist_ok=True)
for name in ("AuthBindingPolicyTest.kt","EphemeralTestSessionTest.kt"):
    copyfile(Path("android-keyprep")/name,ta/name)

build=root/"app/build.gradle.kts"
g=build.read_text()
for marker in ('applicationIdSuffix = ".test.v36hfdiag"',
               'versionCode = 38',
               'versionName = "36.0.2-HF-WEBVIEW-DIAG"',
               'minSdk = 26'):
    assert g.count(marker)==1,marker
g=g.replace('applicationIdSuffix = ".test.v36hfdiag"',
            'applicationIdSuffix = ".test.phase7bind"',1)
g=g.replace('versionCode = 38','versionCode = 1',1)
g=g.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "PHASE7A-ACCOUNT-KEY-MATCH-TEST"',1)
g=g.replace('minSdk = 26','minSdk = 31',1)
g="\n".join(line for line in g.splitlines()
            if not line.strip().startswith(
                ("implementation(","androidTestImplementation(")))+"\n"
assert 'testImplementation("junit:junit:4.13.2")' in g
build.write_text(g)

(main/"res/values/styles.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<resources><style name="Theme.BharathLink" '
    'parent="@android:style/Theme.Material.Light.NoActionBar">'
    '</style></resources>\n'
)

ANDROID="http://schemas.android.com/apk/res/android"
NS="{"+ANDROID+"}"
ET.register_namespace("android",ANDROID)
manifest=ET.Element("manifest")
manifest.set("package","com.bharathlink.app")
perm=ET.SubElement(manifest,"uses-permission")
perm.set(NS+"name","android.permission.INTERNET")
app=ET.SubElement(manifest,"application")
app.set(NS+"label","BharathLink Phase7A TEST")
app.set(NS+"allowBackup","false")
app.set(NS+"usesCleartextTraffic","false")
app.set(NS+"theme","@android:style/Theme.Material.Light.NoActionBar")
activity=ET.SubElement(app,"activity")
activity.set(NS+"name",".phase7.Phase7AuthBindActivity")
activity.set(NS+"exported","true")
activity.set(NS+"label","BharathLink Phase7A TEST")
entry=ET.SubElement(activity,"intent-filter")
ET.SubElement(entry,"action",{NS+"name":"android.intent.action.MAIN"})
ET.SubElement(entry,"category",{NS+"name":"android.intent.category.LAUNCHER"})
ET.ElementTree(manifest).write(main/"AndroidManifest.xml",
    encoding="unicode",xml_declaration=True)
assert len(list(app))==1
assert len(manifest.findall("./uses-permission"))==1
assert perm.get(NS+"name")=="android.permission.INTERNET"

allsource="\n".join(i.read_text() for i in main.rglob("*.kt"))
for forbidden in (
    "SUPABASE_SERVICE_ROLE_KEY","bl20_commit_device_approval",
    "bl20_candidate_proof_finish","register_e2ee_v2_device",
    "KeyStore.deleteEntry","deleteEntry(","addJavascriptInterface",
    "messaging_devices","e2ee_v2_devices","trustedDevice:true",
    "serverApproved:true","e2eeV2Ready:true"):
    assert forbidden not in allsource,forbidden
assert "https://fsdusofbpwdrdvgexxyw.supabase.co" in allsource
assert "LOCAL_ACCOUNT_KEY_MATCH_ONLY_NOT_TRUSTED" in allsource
assert "KeyProperties.PURPOSE_AGREE_KEY" in allsource
assert "auth.getUser" not in allsource # native /auth/v1/user roundtrip used
assert "/auth/v1/user" in allsource
assert "create_user" in allsource and "false" in allsource
assert not any("android.permission." in x and
               x!="android.permission.INTERNET"
               for x in allsource.splitlines())
print("PASS: new-package Phase7A OTP-only TEST app; no existing KeyPrep or approval mutation")
