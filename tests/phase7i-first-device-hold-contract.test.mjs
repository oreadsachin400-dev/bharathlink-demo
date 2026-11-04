import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const get=(p)=>readFileSync(new URL("../"+p,import.meta.url),"utf8");
const hold=get("sql/staged/TEST-first-device-hard-stop-v1.sql");
const issuer=get("sql/staged/TEST-recovery-review-immutable-issuer-pin-v3.sql");
const approval2=get("sql/staged/TEST-device-approval-v2-candidate-possession-gate.sql");
const approvalEdge=get("supabase/functions/bl20-device-approval-v2/index.ts");
const candidateEdge=get("supabase/functions/bl20-candidate-possession/index.ts");
const recoveryEdge=get("supabase/functions/bl20-recovery-v1/index.ts");

test("first-device INSERT blocked without preexisting verified, nonrevoked signer",()=>{
 assert.match(hold,/CREATE TRIGGER hard_stop_first_device_insert_and_rebind/);
 assert.match(hold,/BEFORE INSERT OR UPDATE OF id,user_id,public_key_jwk,key_algorithm,revoked_at/);
 assert.match(hold,/WHERE k.user_id=NEW.user_id AND k.verified_at IS NOT NULL/);
 assert.match(hold,/k.revoked_at IS NULL AND d.revoked_at IS NULL/);
 assert.match(hold,/k.verification_method IN \('trusted_device_signature','audited_recovery'\)/);
 assert.match(hold,/First-device authorization held: no verified signer/);
});
test("first verified signer blocked even for historical unverified device",()=>{
 assert.match(hold,/CREATE TRIGGER hard_stop_first_verified_signer_and_rebind/);
 assert.match(hold,/BEFORE INSERT OR UPDATE OF device_id,user_id,signing_public_key_jwk/);
 assert.match(hold,/IF TG_OP='INSERT' THEN/);
 assert.match(hold,/k.device_id<>NEW.device_id/);
 assert.match(hold,/First verified signing key held pending independent authority/);
});
test("identity and signing ECDH keys cannot be silently re-bound or unrevoked",()=>{
 for(const needle of [
  "NEW.user_id IS DISTINCT FROM OLD.user_id",
  "NEW.public_key_jwk IS DISTINCT FROM OLD.public_key_jwk",
  "NEW.signing_public_key_jwk IS DISTINCT FROM OLD.signing_public_key_jwk",
  "OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL",
  "NEW.verified_at IS DISTINCT FROM OLD.verified_at",
  "FOR SHARE OF k,d"
 ])assert.ok(hold.includes(needle),"missing "+needle);
});
test("hold is private, invoker-only, RLS and no service-client API",()=>{
 assert.match(hold,/CREATE SCHEMA bl20_first_device_hold_private/);
 assert.match(hold,/SECURITY INVOKER/g);
 assert.doesNotMatch(hold,/SECURITY DEFINER/i);
 assert.match(hold,/ALTER TABLE public.messaging_device_signing_keys ENABLE ROW LEVEL SECURITY/);
 assert.match(hold,/REVOKE ALL ON FUNCTION\s+bl20_first_device_hold_private.guard_device_identity\(\)\s+FROM PUBLIC,anon,authenticated,service_role/);
 assert.match(hold,/REVOKE ALL ON FUNCTION\s+bl20_first_device_hold_private.guard_signing_identity\(\)\s+FROM PUBLIC,anon,authenticated,service_role/);
 assert.doesNotMatch(hold,/GRANT EXECUTE|INSERT INTO public.messaging_devices|INSERT INTO public.messaging_device_signing_keys/i);
});
test("existing v2 additional-device path and historical issuer-pins unchanged",()=>{
 assert.match(approval2,/r.approval_protocol_version IS DISTINCT FROM 2/);
 assert.match(approval2,/p.state<>'possession_proven'/);
 assert.match(issuer,/receipt_pin_immutable/);
 assert.match(issuer,/issuer_key_rotation_and_revocation/);
 assert.match(approvalEdge,/const V2_RELEASED=false/);
 assert.match(candidateEdge,/const FEATURE_RELEASED=false/);
 assert.match(recoveryEdge,/const RECOVERY_RELEASED = false/);
});
test("no operational first-device approval, production bypass or APK deployment",()=>{
 for(const bad of [
   /CREATE OR REPLACE FUNCTION public\.bl20_first_device_approve/i,
   /UPDATE\s+public\.messaging_devices.*trusted/i,
   /INSERT INTO bl20_recovery_v1_private\.issuers/i,
   /GRANT\s+(?:INSERT|UPDATE)\s+ON\s+public\.messaging_devices/i,
   /FEATURE_RELEASED=true/i,
   /PLAY_PROTECT_BYPASS/i
 ])assert.doesNotMatch(hold,bad);
});
