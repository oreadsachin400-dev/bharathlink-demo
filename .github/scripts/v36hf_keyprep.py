#!/usr/bin/env python3
"""Integrate isolated native KeyPrep into checksum-verified V36HF TEST build.
Requires startup_rescue + webview_diag scripts to run first. TEST-only."""
from pathlib import Path
from shutil import copyfile
root=Path("v36hf-kotlin-build")
activity_src=Path("android-keyprep/DeviceKeyPrepActivity.kt")
dest=root/"app/src/main/java/com/bharathlink/app/keyprep/DeviceKeyPrepActivity.kt"
assert activity_src.is_file() and root.is_dir()
dest.parent.mkdir(parents=True,exist_ok=True)
copyfile(activity_src,dest)

manifest=root/"app/src/main/AndroidManifest.xml"
s=manifest.read_text()
target='    </application>'
activity='''        <!-- Separate explicit local-only key preparation launcher. No trust enrollment. -->
        <activity
            android:name=".keyprep.DeviceKeyPrepActivity"
            android:exported="true"
            android:label="BharathLink KeyPrep TEST">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
'''
assert s.count(target)==1
manifest.write_text(s.replace(target,activity+target,1))

# The first version exposed TWO launchers: WebView MainActivity plus native KeyPrep.
# On phones with many BharatLink variants the wrong launcher showed the old spinner.
# Make this build a dedicated OFFLINE KeyPrep app with ONE launcher.
import xml.etree.ElementTree as ET
ANDROID='http://schemas.android.com/apk/res/android'
ANAME='{'+ANDROID+'}name'
AEXPORTED='{'+ANDROID+'}exported'
ET.register_namespace('android', ANDROID)
tree=ET.parse(manifest)
document=tree.getroot()
app=document.find('application')
assert app is not None
prep='.keyprep.DeviceKeyPrepActivity'
launchers=[]
for entry in list(app):
    if entry.tag not in ('activity','activity-alias'):
        continue
    name=entry.get(ANAME,'')
    for filt in list(entry):
        if filt.tag!='intent-filter':
            continue
        actions=[x.get(ANAME) for x in filt.findall('action')]
        categories=[x.get(ANAME) for x in filt.findall('category')]
        if 'android.intent.action.MAIN' in actions and 'android.intent.category.LAUNCHER' in categories:
            if name==prep:
                launchers.append(name)
            else:
                entry.remove(filt)
                entry.set(AEXPORTED,'false')
                print('HID_OLD_LAUNCHER:', name)
# No need to ship internet permission in local-only key preparation utility.
for entry in list(document):
    if entry.tag in ('uses-permission','uses-permission-sdk-23') and entry.get(ANAME)=='android.permission.INTERNET':
        document.remove(entry)
app.set('{'+ANDROID+'}label','BharathLink KeyPrep TEST')
app.set('{'+ANDROID+'}allowBackup','false')
app.set('{'+ANDROID+'}usesCleartextTraffic','false')
assert launchers==[prep], f'Expected only one KeyPrep launcher, got {launchers}'
for entry in app:
    if entry.tag in ('activity','activity-alias') and entry.get(ANAME)!=prep:
        for filt in entry.findall('intent-filter'):
            actions=[x.get(ANAME) for x in filt.findall('action')]
            categories=[x.get(ANAME) for x in filt.findall('category')]
            assert not ('android.intent.action.MAIN' in actions and 'android.intent.category.LAUNCHER' in categories)
assert not any(e.get(ANAME)=='android.permission.INTERNET' for e in document.findall('uses-permission'))
tree.write(manifest, encoding='unicode', xml_declaration=True)


gradle=root/"app/build.gradle.kts"
s=gradle.read_text()
assert s.count('applicationIdSuffix = ".test.v36hfdiag"')==1
assert s.count('versionCode = 38')==1
assert s.count('versionName = "36.0.2-HF-WEBVIEW-DIAG"')==1
s=s.replace('applicationIdSuffix = ".test.v36hfdiag"','applicationIdSuffix = ".test.keypreponly"',1)
s=s.replace('versionCode = 38','versionCode = 40',1)
s=s.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "36.0.4-HF-KEYPREP-ONLY"',1)
gradle.write_text(s)
source=dest.read_text()
assert "BharathLink KeyPrep TEST" in manifest.read_text()
assert "serverApproved\", false" in source
assert "e2eeV2Ready\", false" in source
assert 'addJavascriptInterface' not in source
assert 'KeyProperties.PURPOSE_AGREE_KEY' in source
assert 'KeyProperties.PURPOSE_SIGN' in source
print("KEYPREP_ONLY_INTEGRATION_PASS: only native launcher; no Internet permission; isolated package; keys local-only")
