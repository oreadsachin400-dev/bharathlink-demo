#!/usr/bin/env python3
"""Compile-only native TEST email OTP and local key account binding.
The installed KeyPrep app has real keystore keys: DO NOT publish a new APK with
a GitHub-generated ephemeral debug signing key (uninstall destroys its keys).
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root=Path("v36hf-kotlin-build")
src=Path("android-keyprep")
dest=root/"app/src/main/java/com/bharathlink/app/keyprep"
dest.mkdir(parents=True,exist_ok=True)
for file in ["NativeTestAuth.kt","NativeAuthConfig.kt","NativeAuthBindActivity.kt",
             "EphemeralTestSession.kt",
             "AuthBindingPolicy.kt","LocalBindingGate.kt"]:
    assert (src/file).is_file(),file
    copyfile(src/file,dest/file)

prep=dest/"DeviceKeyPrepActivity.kt"
s=prep.read_text()
needle='        action("PREPARE LOCAL P-256 KEYS — TEST") { runAction(true) }\n'
assert s.count(needle)==1
s=s.replace(needle,needle+'''        action("VERIFY EXISTING TEST ACCOUNT (NATIVE)") {
            startActivity(android.content.Intent(this,NativeAuthBindActivity::class.java))
        }
''')
prep.write_text(s)
assert 'signCandidateServerChallenge' in s

test_dir=root/"app/src/test/java/com/bharathlink/app/keyprep"
test_dir.mkdir(parents=True,exist_ok=True)
copyfile(src/"AuthBindingPolicyTest.kt",test_dir/"AuthBindingPolicyTest.kt")
copyfile(src/"LocalBindingGateTest.kt",test_dir/"LocalBindingGateTest.kt")
copyfile(src/"EphemeralTestSessionTest.kt",test_dir/"EphemeralTestSessionTest.kt")

manifest=root/"app/src/main/AndroidManifest.xml"
ET.register_namespace("android","http://schemas.android.com/apk/res/android")
ns="{http://schemas.android.com/apk/res/android}"
tree=ET.parse(manifest)
document=tree.getroot()
app=document.find("application")
assert app is not None
assert not any(e.get(ns+"name")==".keyprep.NativeAuthBindActivity" for e in app.findall("activity"))
authActivity=ET.SubElement(app,"activity")
authActivity.set(ns+"name",".keyprep.NativeAuthBindActivity")
authActivity.set(ns+"exported","false")
authActivity.set(ns+"label","Native TEST Auth Bind")
# A guarded, native-only auth flow needs HTTPS. Keep cleartext disallowed.
perm=ET.SubElement(document,"uses-permission")
perm.set(ns+"name","android.permission.INTERNET")
assert app.get(ns+"usesCleartextTraffic")=="false"
assert app.get(ns+"allowBackup")=="false"
assert sum(a.get(ns+"name")=="android.permission.INTERNET" for a in document.findall("uses-permission"))==1
# Keep old WebView MAIN launcher hidden; native KeyPrep is the only launch entry.
launchers=[]
for entry in app:
    if entry.tag in ("activity","activity-alias"):
        for filt in entry.findall("intent-filter"):
            acts=[x.get(ns+"name") for x in filt.findall("action")]
            cats=[x.get(ns+"name") for x in filt.findall("category")]
            if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                launchers.append(entry.get(ns+"name"))
assert launchers==[".keyprep.DeviceKeyPrepActivity"],launchers
tree.write(manifest,encoding="unicode",xml_declaration=True)

gradle=root/"app/build.gradle.kts"
g=gradle.read_text()
assert g.count('applicationIdSuffix = ".test.keypreponly"')==1
assert g.count('versionCode = 40')==1
assert g.count('versionName = "36.0.4-HF-KEYPREP-ONLY"')==1
g=g.replace("versionCode = 40","versionCode = 41")
g=g.replace('versionName = "36.0.4-HF-KEYPREP-ONLY"',
            'versionName = "36.0.5-HF-AUTH-BIND-STAGED"')
gradle.write_text(g)
assert "bl20_commit_device_approval" not in (dest/"NativeTestAuth.kt").read_text()
assert "request_messaging_device_enrollment" not in (dest/"NativeTestAuth.kt").read_text()
print("NATIVE_AUTH_BIND_STAGING_PASS: same package, one launcher, HTTPS, no trust writes")
