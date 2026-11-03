#!/usr/bin/env python3
"""Stage a disposable OFFLINE Android P-256 self-test app in a distinct package.
No Internet, no Supabase, no old KeyPrep access, no key migration or approval.
All original repository archive and live Android packages remain unchanged.
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root=Path("v36hf-kotlin-build")
main=root/"app/src/main"
src=Path("android-freshprep")
assert main.is_dir() and src.is_dir()

# Purge inherited app code and tests from the temporary build ONLY.
for parent in (main,root/"app/src/test"):
    if parent.is_dir():
        for old in parent.rglob("*"):
            if old.is_file() and old.suffix in (".kt",".java"):
                old.unlink()

dest=main/"java/com/bharathlink/app/freshprep"
dest.mkdir(parents=True,exist_ok=True)
for file in ("FreshKeyPrepActivity.kt","OfflineProofPolicy.kt"):
    copyfile(src/file,dest/file)
test_dir=root/"app/src/test/java/com/bharathlink/app/freshprep"
test_dir.mkdir(parents=True,exist_ok=True)
copyfile(src/"OfflineProofPolicyTest.kt",test_dir/"OfflineProofPolicyTest.kt")

gradle=root/"app/build.gradle.kts"
s=gradle.read_text(encoding="utf-8")
assert s.count('applicationIdSuffix = ".test.v36hfdiag"')==1
assert s.count('versionCode = 38')==1
assert s.count('versionName = "36.0.2-HF-WEBVIEW-DIAG"')==1
s=s.replace('applicationIdSuffix = ".test.v36hfdiag"',
            'applicationIdSuffix = ".test.freshprep"',1)
s=s.replace('versionCode = 38','versionCode = 1',1)
s=s.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "PHASE6-OFFLINE-FRESH-P256-SELFTEST"',1)
# Remove unnecessary dependencies to prevent manifest-merged permissions,
# receivers or services. Keep JUnit for pure offline policy tests.
s=chr(10).join(line for line in s.splitlines()
               if not line.strip().startswith(("implementation(", "androidTestImplementation(")))+chr(10)
assert 'testImplementation("junit:junit:4.13.2")' in s
gradle.write_text(s,encoding="utf-8")

# Old app's MaterialComponents theme no longer exists after dependency stripping.
styles=main/"res/values/styles.xml"
styles.write_text('<?xml version="1.0" encoding="utf-8"?>'+chr(10)+
    '<resources><style name="Theme.BharathLink" '
    'parent="@android:style/Theme.Material.Light.NoActionBar">'
    '</style></resources>'+chr(10),encoding="utf-8")

ns="{http://schemas.android.com/apk/res/android}"
ET.register_namespace("android","http://schemas.android.com/apk/res/android")
manifest=main/"AndroidManifest.xml"
tree=ET.parse(manifest)
doc=tree.getroot()
app=doc.find("application")
assert app is not None
for child in list(app):
    if child.tag in ("activity","activity-alias","provider","service","receiver"):
        app.remove(child)
for child in list(doc):
    if child.tag.startswith("uses-permission") or child.tag=="queries":
        doc.remove(child)

app.set(ns+"label","BharathLink Fresh KeyPrep TEST")
app.set(ns+"allowBackup","false")
app.set(ns+"usesCleartextTraffic","false")
activity=ET.SubElement(app,"activity")
activity.set(ns+"name",".freshprep.FreshKeyPrepActivity")
activity.set(ns+"exported","true")
activity.set(ns+"label","BharathLink Fresh KeyPrep TEST")
it=ET.SubElement(activity,"intent-filter")
ET.SubElement(it,"action").set(ns+"name","android.intent.action.MAIN")
ET.SubElement(it,"category").set(ns+"name","android.intent.category.LAUNCHER")
assert len(app.findall("activity"))==1
assert not any(x.tag.startswith("uses-permission") for x in doc)
assert not doc.findall("queries")
tree.write(manifest,encoding="unicode",xml_declaration=True)

files=list(dest.rglob("*.kt"))
assert len(files)==2
contents="\\n".join(x.read_text(encoding="utf-8") for x in files)
for forbidden in (
    "SUPABASE_SERVICE_ROLE_KEY","supabase.co","NativeAuthClient","HttpURLConnection",
    "bl20_commit_device_approval","bl20_recovery_v1_review_consume_v2",
    "register_e2ee_v2_device","LOCAL_KEYS_ONLY_NOT_VERIFIED_PRODUCTION",
    "addJavascriptInterface", "deleteEntry(", "KeyStore.deleteEntry",
):
    assert forbidden not in contents,forbidden

assert "LOCAL_CRYPTO_SELF_TEST_PASS" in contents
assert "LOCAL_CRYPTO_SELF_TEST_ONLY_NOT_TRUSTED" in contents
assert "AndroidKeyStore" in contents
assert "setOnClickListener { createOnce() }" in contents
print("PASS: distinct app package, local-only P-256 creation on explicit tap, no permissions")
