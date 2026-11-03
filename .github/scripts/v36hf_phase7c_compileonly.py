#!/usr/bin/env python3
"""Compile the Phase7C native TEST proof adapter without publishing an APK.

Stages from pinned V36HF disposable scaffolding after Phase7A and Phase7B.
No remote Supabase operations or existing device-key migration.
"""
from pathlib import Path
from shutil import copyfile

root=Path("v36hf-kotlin-build")
sources=root/"app/src/main/java/com/bharathlink/app/phase7"
tests=root/"app/src/test/java/com/bharathlink/app/phase7"
assert sources.is_dir() and tests.is_dir()
for name in ("Phase7cProofCoordinator.kt", "Phase7cTestHttpsTransport.kt",
             "Phase7cPreparedNativeFlow.kt"):
    assert not (sources/name).exists()
    copyfile(Path("android-phase7c")/name, sources/name)
test="Phase7cProofCoordinatorTest.kt"
assert not (tests/test).exists()
copyfile(Path("android-phase7c")/test,tests/test)

source="\n".join(p.read_text() for p in sources.glob("Phase7c*.kt"))
assert "Phase7bCandidateSigner.signProofFromAuthenticatedTestSession(" in source
assert "Phase7cProofCoordinator(" in source
assert "https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bl20-candidate-possession" in source
assert "session.isForeground()" in source
assert "verified.invalidate()" in source
assert "conn.instanceFollowRedirects=false" in source
for forbidden in (
    "SUPABASE_SERVICE_ROLE_KEY", "KeyStore.deleteEntry",
    "addJavascriptInterface", "bl20_commit_device_approval",
    "register_e2ee_v2_device", "serverApproved=true", "trustedDevice=true",
    "phase7cEnrollButton.setOnClickListener"):
    assert forbidden not in source,forbidden
manifest=(root/"app/src/main/AndroidManifest.xml").read_text()
assert manifest.count("android.permission.INTERNET")==1
assert manifest.count("<activity")==1
assert 'applicationIdSuffix = ".test.phase7bind"' in (
    root/"app/build.gradle.kts").read_text()
assert "const FEATURE_RELEASED=false" in Path(
    "supabase/functions/bl20-candidate-possession/index.ts").read_text()
print("PASS: Phase7C source-only, pinned TEST host, single permission, hard remote gate")
