import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync, existsSync} from "node:fs";

const source = path => readFileSync(new URL("../"+path,import.meta.url),"utf8");
const manifest = JSON.parse(source("docs/security-release-readiness.json"));

test("release is explicitly held regardless of green CI", () => {
  assert.equal(manifest.release_decision,"HOLD");
  for(const k of ["is_production_authorized","is_test_apk_install_approved",
    "may_activate_first_device","may_enable_live_e2ee"])assert.equal(manifest[k],false,k);
  assert.equal(manifest.release_blockers.length,8);
  for(const item of manifest.release_blockers) {
    assert.ok(item.id && item.status && item.evidence && item.next_action);
    assert.notEqual(item.status,"PASS");
    assert.notEqual(item.status,"DONE");
  }
  for(const k of Object.keys(manifest.policy))assert.equal(manifest.policy[k],true,k);
});
test("all known CI checkpoints are explicitly synthetic/staged, not runtime approvals",()=>{
  assert.equal(manifest.checkpoints.length,8);
  for(const item of manifest.checkpoints){
    assert.equal(item.state,"CI_PASS");
    assert.notEqual(item.type,"production");
    assert.notEqual(item.type,"live");
  }
});
test("candidate, approval, issuer recovery release gates remain hard-disabled",()=>{
  for(const [path,needle] of [
    ["supabase/functions/bl20-candidate-possession/index.ts",
      "const FEATURE_RELEASED=false;"],
    ["supabase/functions/bl20-device-approval/index.ts",
      "const APPROVAL_FEATURE_RELEASED = false;"],
    ["supabase/functions/bl20-device-approval-v2/index.ts",
      "const V2_RELEASED=false;"],
    ["supabase/functions/bl20-recovery-v1/index.ts",
      "const RECOVERY_RELEASED = false;"]
  ])assert.ok(source(path).includes(needle),path);
});
test("staged governance is not an activated first-device permission",()=>{
  const gov=source("sql/staged/TEST-first-device-governance-intent-v1.sql");
  const hold=source("sql/staged/TEST-first-device-hard-stop-v1.sql");
  const pin=source("sql/staged/TEST-recovery-review-immutable-issuer-pin-v3.sql");
  assert.match(gov,/governance_pending_review_only/);
  assert.match(gov,/governance_vetoed/);
  assert.match(hold,/First-device authorization held: no verified signer/);
  assert.match(hold,/First verified signing key held pending independent authority/);
  assert.match(pin,/issuer_key_rotation_and_revocation/);
  for(const text of [gov,hold,pin]){
    assert.doesNotMatch(text,/\bINSERT\s+INTO\s+public\.messaging_devices/i);
    assert.doesNotMatch(text,/bl20_first_device_approve\s*\(/i);
  }
});
test("signer continuity preflight is present and protected KeyPrep source retained",()=>{
  for(const path of [
    "scripts/check_keyprep_release.py",
    "scripts/check_keyprep_signing.py",
    "tests/test_signing_preflight.py",
    ".github/workflows/keyprep-protected-signing.yml",
    "BharathLink-V36HF-SecurityPatch-TEST-SOURCE-READY.zip"
  ])assert.ok(existsSync(new URL("../"+path,import.meta.url)),path);
  assert.match(source("docs/KeyPrep-Signing-and-OTP-Release-Gate-2026-11-02.md"),
    /ephemeral\/differing GitHub debug signing/);
});
test("readiness matrix separates CI, physical tests, external third-party gates",()=>{
 const blockers = new Set(manifest.release_blockers.map(v=>v.id));
 for(const id of [
   "PLAY_PROTECT","SIGNING_CONTINUITY","OTP_TEMPLATE_AND_DELIVERY",
   "ANDROID_LIVE_CHALLENGE","REAL_IDENTITY_ISSUER",
   "FIRST_DEVICE_AUTHORIZATION","TWO_PHONE_E2EE_AND_FEATURES",
   "INDEPENDENT_SECURITY_REVIEW"
 ])assert.ok(blockers.has(id),id);
});

test("old Phase7A distribution workflow is permanently compile-only while harmful-app warning unresolved",()=>{
  const w=source(".github/workflows/phase7a-isolated-auth-binding-android.yml");
  assert.match(w,/PLAY PROTECT HOLD/);
  assert.match(w,/:app:testDebugUnitTest/);
  assert.doesNotMatch(w,/:app:assembleDebug/);
  assert.doesNotMatch(w,/actions\/upload-artifact@/);
  assert.doesNotMatch(w,/apksigner\s+sign\b/);
  assert.match(w,/test ! -d v36hf-kotlin-build\/app\/build\/outputs\/apk/);
});
