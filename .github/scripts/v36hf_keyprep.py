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

gradle=root/"app/build.gradle.kts"
s=gradle.read_text()
assert s.count('applicationIdSuffix = ".test.v36hfdiag"')==1
assert s.count('versionCode = 38')==1
assert s.count('versionName = "36.0.2-HF-WEBVIEW-DIAG"')==1
s=s.replace('applicationIdSuffix = ".test.v36hfdiag"','applicationIdSuffix = ".test.keyprep"',1)
s=s.replace('versionCode = 38','versionCode = 39',1)
s=s.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
            'versionName = "36.0.3-HF-KEYPREP-TEST"',1)
gradle.write_text(s)
source=dest.read_text()
assert "BharathLink KeyPrep TEST" in manifest.read_text()
assert "serverApproved\", false" in source
assert "e2eeV2Ready\", false" in source
assert 'addJavascriptInterface' not in source
assert 'KeyProperties.PURPOSE_AGREE_KEY' in source
assert 'KeyProperties.PURPOSE_SIGN' in source
print("KEYPREP_INTEGRATION_PASS: 2nd launcher, isolated package, local-only keys, no server calls")
