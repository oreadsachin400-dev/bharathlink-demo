#!/usr/bin/env python3
"""Create disposable OFFLINE package-signature inspection APK from pinned V36HF.

Distinct app ID; does not update KeyPrep, request network, call auth or access
AndroidKeyStore. Only uses PackageManager to inspect publicly exposed package
signature metadata. Build in a GitHub CI TEMP directory; no private key needed.
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root=Path("v36hf-kotlin-build")
main=root/"app/src/main"
assert main.is_dir()
# Remove inherited original app Java/Kotlin implementation, not the resources.
for parent in (main,root/"app/src/test"):
    if parent.is_dir():
        for src in parent.rglob("*"):
            if src.is_file() and src.suffix in (".java",".kt"):
                src.unlink()

dest=main/"java/com/bharathlink/app/signingaudit"
dest.mkdir(parents=True,exist_ok=True)
for name in ("SigningAuditActivity.kt","SignerEvidencePolicy.kt"):
    copyfile(Path("android-signing-inspector")/name,dest/name)

test_dir=root/"app/src/test/java/com/bharathlink/app/signingaudit"
test_dir.mkdir(parents=True,exist_ok=True)
copyfile("android-signing-inspector/SignerEvidencePolicyTest.kt",
         test_dir/"SignerEvidencePolicyTest.kt")

gradle=root/"app/build.gradle.kts"
s=gradle.read_text(encoding="utf-8")
assert s.count('applicationIdSuffix = ".test.v36hfdiag"')==1
assert s.count('versionCode = 38')==1
assert s.count('versionName = "36.0.2-HF-WEBVIEW-DIAG"')==1
s=s.replace('applicationIdSuffix = ".test.v36hfdiag"',
            'applicationIdSuffix = ".test.signingaudit"',1)
s=s.replace('versionCode = 38','versionCode = 1',1)
s=s.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "SIGNER-INSPECTOR-1-TEST"',1)
# Purge old WebView/AppCompat/network/crypto dependencies: this is ONLY an
# Android platform PackageManager inspector. JUnit still runs in CI.
import re
s=re.sub(r"(?m)^\\s*(?:implementation|androidTestImplementation)\\([^\\n]*\\)\\s*\\n","",s)
assert 'implementation("androidx.core' not in s
assert 'implementation("com.google.android.material' not in s
assert 'testImplementation("junit:junit:4.13.2")' in s
gradle.write_text(s,encoding="utf-8")

# The inherited MaterialComponents theme would require the removed UI library.
# Use the Android platform theme instead; no external UI library needed.
styles=main/"res/values/styles.xml"
styles.write_text('<?xml version="1.0" encoding="utf-8"?>\\n'
                  '<resources><style name="Theme.BharathLink" '
                  'parent="@android:style/Theme.Material.Light.NoActionBar">'
                  '</style></resources>\\n',encoding="utf-8")

manifest=main/"AndroidManifest.xml"
ns="{http://schemas.android.com/apk/res/android}"
ET.register_namespace("android","http://schemas.android.com/apk/res/android")
tree=ET.parse(manifest)
doc=tree.getroot()
app=doc.find("application")
assert app is not None

for child in list(app):
    if child.tag in ("activity","activity-alias","provider","service","receiver"):
        app.remove(child)
for child in list(doc):
    if child.tag.startswith("uses-permission"):
        doc.remove(child)

# Android 11+ strict package visibility: query ONLY known KeyPrep package.
for child in list(doc):
    if child.tag=="queries":
        doc.remove(child)
queries=ET.Element("queries")
package=ET.SubElement(queries,"package")
package.set(ns+"name","com.bharathlink.app.test.keypreponly")
doc.insert(0,queries)

app.set(ns+"label","BharathLink Signer Inspector TEST")
app.set(ns+"allowBackup","false")
app.set(ns+"usesCleartextTraffic","false")
activity=ET.SubElement(app,"activity")
activity.set(ns+"name",".signingaudit.SigningAuditActivity")
activity.set(ns+"exported","true")
activity.set(ns+"label","BharathLink Signer Inspector TEST")
filter=ET.SubElement(activity,"intent-filter")
act=ET.SubElement(filter,"action")
act.set(ns+"name","android.intent.action.MAIN")
cat=ET.SubElement(filter,"category")
cat.set(ns+"name","android.intent.category.LAUNCHER")

assert len(app.findall("activity"))==1
assert not doc.findall("uses-permission")
assert len(doc.findall("queries"))==1
assert package.get(ns+"name")=="com.bharathlink.app.test.keypreponly"
source=(dest/"SigningAuditActivity.kt").read_text()
assert "getPackageInfo" in source and "GET_SIGNING_CERTIFICATES" in source
for forbidden in ("LocalApprovalKeys","AndroidKeyStore","KeyStore.getInstance",
                  "HttpURLConnection","SUPABASE_SERVICE_ROLE_KEY",
                  "bl20_commit_device_approval","register_e2ee_v2_device",
                  "FileOutputStream","deletePackage","deleteKey"):
    assert forbidden not in source,forbidden
tree.write(manifest,encoding="unicode",xml_declaration=True)
print("SIGNER_INSPECTOR_STAGING_PASS: isolated package, no permissions, no keys, read-only")
