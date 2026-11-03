#!/usr/bin/env python3
"""Compile-only Android signer integration on top of existing isolated 7A TEST.
Never creates an APK artifact, never changes original KeyPrep, no remote writes.
"""
from pathlib import Path
from shutil import copyfile

root=Path("v36hf-kotlin-build")
source=root/"app/src/main/java/com/bharathlink/app/phase7"
tests=root/"app/src/test/java/com/bharathlink/app/phase7"
assert source.is_dir() and tests.is_dir()
for name in ("Phase7bChallengePolicy.kt","Phase7bCandidateSigner.kt"):
    dest=source/name
    assert not dest.exists(),f"Refuse to overwrite: {dest}"
    copyfile(Path("android-phase7b")/name,dest)
name="Phase7bChallengePolicyTest.kt"
assert not (tests/name).exists()
copyfile(Path("android-phase7b")/name,tests/name)

sign=(source/"Phase7bCandidateSigner.kt").read_text()
policy=(source/"Phase7bChallengePolicy.kt").read_text()
assert "BHARATHLINK_CANDIDATE_POSSESSION_V1" in policy
assert "bharathlink_phase7a_disposable_sign" in sign
assert "bharathlink_phase7a_disposable_ecdh" in sign
assert "KeyStore.getInstance(\"AndroidKeyStore\")" in sign
assert "Signature.getInstance(\"SHA256withECDSA\")" in sign
assert "sessionValidInForeground" in sign
for name in ("deleteEntry(","generateKeyPair(","SUPABASE_SERVICE_ROLE_KEY",
             "bl20_commit_device_approval","register_e2ee_v2_device",
             "HttpURLConnection","addJavascriptInterface","getRefreshToken",
             "serverApproved=true","trustedDevice=true"):
    assert name not in sign and name not in policy,name
g=(root/"app/build.gradle.kts").read_text()
assert 'applicationIdSuffix = ".test.phase7bind"' in g
assert 'versionCode = 1' in g
manifest=(root/"app/src/main/AndroidManifest.xml").read_text()
assert manifest.count("android.permission.INTERNET")==1
assert "com.bharathlink.app.test.keypreponly" not in manifest
print("PASS: native signer compiled ONLY for unchanged separate Phase7A TEST sandbox")
