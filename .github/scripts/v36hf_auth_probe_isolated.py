#!/usr/bin/env python3
"""Build a disposable auth-only APK alongside, NOT over, physical KeyPrep-only.

No native AndroidKeyStore credentials can cross application package boundaries.
No private-key generation/import and no attempt to carry over old trusted-device
claims or same-package signing identity. Ephemeral debug certificate is permitted
for a one-off *stateless* probe, not for any long-lived enrollment keys.
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root=Path("v36hf-kotlin-build")
src=Path("android-keyprep")
dest=root/"app/src/main/java/com/bharathlink/app/keyprep"
dest.mkdir(parents=True,exist_ok=True)
copyfile(Path("android-auth-probe/NativeAuthProbeActivity.kt"), dest/"NativeAuthProbeActivity.kt")
for file in ("NativeTestAuth.kt","NativeAuthConfig.kt","EphemeralTestSession.kt","AuthBindingPolicy.kt"):
    copyfile(src/file,dest/file)

test_dir=root/"app/src/test/java/com/bharathlink/app/keyprep"
test_dir.mkdir(parents=True,exist_ok=True)
for file in ("AuthBindingPolicyTest.kt","EphemeralTestSessionTest.kt"):
    copyfile(src/file,test_dir/file)

gradle=root/"app/build.gradle.kts"
s=gradle.read_text()
assert s.count('applicationIdSuffix = ".test.v36hfdiag"')==1
assert s.count('versionCode = 38')==1
assert s.count('versionName = "36.0.2-HF-WEBVIEW-DIAG"')==1
s=s.replace('applicationIdSuffix = ".test.v36hfdiag"',
            'applicationIdSuffix = ".test.authprobe"',1)
s=s.replace('versionCode = 38','versionCode = 1',1)
s=s.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "AUTH-PROBE-ONLY-1.0-TEST"',1)
gradle.write_text(s)

manifest=root/"app/src/main/AndroidManifest.xml"
ns="{http://schemas.android.com/apk/res/android}"
ET.register_namespace("android","http://schemas.android.com/apk/res/android")
tree=ET.parse(manifest)
doc=tree.getroot()
app=doc.find("application")
assert app is not None

# Delete old WebView launcher/providers/services/receivers: no unneeded entrypoints.
for child in list(app):
    if child.tag in ("activity","activity-alias","provider","service","receiver"):
        app.remove(child)

# Strict minimum normal permission. No camera, phone, contacts, SMS, storage.
for node in list(doc):
    if node.tag.startswith("uses-permission"):
        doc.remove(node)
permission=ET.Element("uses-permission")
permission.set(ns+"name","android.permission.INTERNET")
doc.insert(0,permission)

app.set(ns+"label","BharathLink Auth Probe TEST")
app.set(ns+"allowBackup","false")
app.set(ns+"usesCleartextTraffic","false")
activity=ET.SubElement(app,"activity")
activity.set(ns+"name",".keyprep.NativeAuthProbeActivity")
activity.set(ns+"exported","true")
activity.set(ns+"label","BharathLink Auth Probe TEST")
intent=ET.SubElement(activity,"intent-filter")
action=ET.SubElement(intent,"action")
action.set(ns+"name","android.intent.action.MAIN")
category=ET.SubElement(intent,"category")
category.set(ns+"name","android.intent.category.LAUNCHER")
assert len(app.findall("activity"))==1
assert len(doc.findall("uses-permission"))==1
assert doc.find("uses-permission").get(ns+"name")=="android.permission.INTERNET"
assert not any(entry.get(ns+"name")==".keyprep.DeviceKeyPrepActivity"
  for entry in app.findall("activity"))
tree.write(manifest,encoding="unicode",xml_declaration=True)

source=(dest/"NativeAuthProbeActivity.kt").read_text()
assert "LocalApprovalKeys" not in source
assert "KeyStore" not in source
assert "SUPABASE_SERVICE_ROLE_KEY" not in source
assert "create_user\", false" in (dest/"NativeTestAuth.kt").read_text()
assert "bl20_commit_device_approval" not in source
assert "bl20_candidate_proof_start" not in source
assert "register_e2ee_v2_device" not in source
assert "EphemeralTestSession" in (dest/"NativeTestAuth.kt").read_text()
print("AUTH_PROBE_ISOLATED: different app ID, one launcher, INTERNET only, no KeyStore, no trust writes")
