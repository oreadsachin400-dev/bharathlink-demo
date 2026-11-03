#!/usr/bin/env python3
"""Stage a NEW offline-only Android fresh-device P-256 self-test app.

This is a disposable TEST APK with a distinct app ID. It never reads, updates,
uninstalls, re-labels, or accesses the existing KeyPrep app/private keys.
It uses a SHA-256-pinned archived source as build scaffolding only.
"""
from pathlib import Path
from shutil import copyfile
import xml.etree.ElementTree as ET

root = Path("v36hf-kotlin-build")
main = root / "app/src/main"
assert main.is_dir()

# Remove all inherited WebView, notification, bridge and previous app sources.
for parent in (main, root / "app/src/test"):
    if parent.is_dir():
        for f in parent.rglob("*"):
            if f.is_file() and f.suffix in (".java", ".kt"):
                f.unlink()

dest = main / "java/com/bharathlink/app/freshprep"
dest.mkdir(parents=True, exist_ok=True)
for file in ("FreshKeyPrepActivity.kt", "OfflineProofPolicy.kt"):
    copyfile(Path("android-freshprep") / file, dest / file)

test_dir = root / "app/src/test/java/com/bharathlink/app/freshprep"
test_dir.mkdir(parents=True, exist_ok=True)
copyfile(Path("android-freshprep") / "OfflineProofPolicyTest.kt",
         test_dir / "OfflineProofPolicyTest.kt")

gradle = root / "app/build.gradle.kts"
g = gradle.read_text(encoding="utf-8")
for value in ('applicationIdSuffix = ".test.v36hfdiag"',
              'versionCode = 38', 'versionName = "36.0.2-HF-WEBVIEW-DIAG"',
              'minSdk = 26'):
    assert g.count(value) == 1, value
g = g.replace('applicationIdSuffix = ".test.v36hfdiag"',
              'applicationIdSuffix = ".test.freshprep"', 1)
g = g.replace('versionCode = 38', 'versionCode = 1', 1)
g = g.replace('versionName = "36.0.2-HF-WEBVIEW-DIAG"',
              'versionName = "FRESH-OFFLINE-PREP-1-TEST"', 1)
# Android Keystore PURPOSE_AGREE_KEY starts at Android API 31.
g = g.replace('minSdk = 26', 'minSdk = 31', 1)
g = "\n".join(line for line in g.splitlines()
              if not line.strip().startswith(
                  ("implementation(", "androidTestImplementation("))) + "\n"
assert 'testImplementation("junit:junit:4.13.2")' in g
assert 'applicationIdSuffix = ".test.freshprep"' in g
gradle.write_text(g, encoding="utf-8")

# The original resources still refer to MaterialComponents, now removed.
# Override the unused scaffold theme with a platform style for AAPT linking.
styles = main / "res/values/styles.xml"
styles.write_text(
    '<?xml version="1.0" encoding="utf-8"?>' + chr(10) +
    '<resources><style name="Theme.BharathLink" '
    'parent="@android:style/Theme.Material.Light.NoActionBar">'
    '</style></resources>' + chr(10), encoding="utf-8"
)

# Replace the entire manifest: exactly one launcher, no permissions/queries/
# providers/receivers/services, and no network or backup.
ANDROID = "http://schemas.android.com/apk/res/android"
NS = "{" + ANDROID + "}"
ET.register_namespace("android", ANDROID)
manifest = ET.Element("manifest")
manifest.set("package", "com.bharathlink.app")
app = ET.SubElement(manifest, "application")
app.set(NS + "label", "BharathLink Fresh Prep TEST")
app.set(NS + "allowBackup", "false")
app.set(NS + "usesCleartextTraffic", "false")
app.set(NS + "theme", "@android:style/Theme.Material.Light.NoActionBar")
activity = ET.SubElement(app, "activity")
activity.set(NS + "name", ".freshprep.FreshKeyPrepActivity")
activity.set(NS + "exported", "true")
activity.set(NS + "label", "BharathLink Fresh Prep TEST")
entry = ET.SubElement(activity, "intent-filter")
action = ET.SubElement(entry, "action")
action.set(NS + "name", "android.intent.action.MAIN")
cat = ET.SubElement(entry, "category")
cat.set(NS + "name", "android.intent.category.LAUNCHER")

manifest_path = main / "AndroidManifest.xml"
ET.ElementTree(manifest).write(
    manifest_path, encoding="unicode", xml_declaration=True
)
assert len(manifest.findall(".//activity")) == 1
assert not any(node.tag.startswith("uses-") for node in manifest)
assert len(list(app)) == 1

source = (dest / "FreshKeyPrepActivity.kt").read_text(encoding="utf-8")
policy = (dest / "OfflineProofPolicy.kt").read_text(encoding="utf-8")
assert 'KeyStore.getInstance("AndroidKeyStore")' in source
assert 'KeyProperties.PURPOSE_AGREE_KEY' in source
assert 'setUserAuthenticationRequired' not in source
assert 'LOCAL_CRYPTO_SELF_TEST_PASS' in source
assert "BHARATHLINK_FRESH_DEVICE_OFFLINE_SELFTEST_V1" in policy
assert "LOCAL_TEST_ONLY_NO_ENROLLMENT" in policy
for forbidden in (
    "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY", "https://",
    "HttpURLConnection", "OkHttpClient", "register_e2ee_v2_device",
    "bl20_commit_device_approval", "bl20_recovery_v1_review_consume",
    "LocalApprovalKeys", "DeviceKeyPrepActivity",
    "KeyStore.deleteEntry", "KeyStore.setEntry", "KeyStore.loadKey",
    "android.permission", "addJavascriptInterface"
):
    assert forbidden not in source and forbidden not in policy, forbidden
print("PASS: standalone no-permission offline TEST app; old KeyPrep untouched")
