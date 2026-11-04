import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const root=new URL("../",import.meta.url);
const read=p=>readFileSync(new URL(p,root),"utf8");
const sql=read("sql/staged/TEST-recovery-review-immutable-issuer-pin-v3.sql");
const recovery=read("supabase/functions/bl20-recovery-v1/index.ts");
const candidate=read("supabase/functions/bl20-candidate-possession/index.ts");
const approved=read("supabase/functions/bl20-device-approval/index.ts");
const approved2=read("supabase/functions/bl20-device-approval-v2/index.ts");
test("receipt pin records actual immutable issuer key and signature SHA at consumption",()=>{
 for(const x of [
 "CREATE TABLE bl20_issuer_pin_v1_private.receipt_pins",
 "issuer_public_jwk jsonb NOT NULL",
 "issuer_public_key_sha256 text NOT NULL",
 "attestation_sha256 text NOT NULL",
 "public.bl20_recovery_v1_review_consume_v3",
 "public.bl20_recovery_v1_review_consume_v2(",
 "challenge_id,case_id,issuer_id,issuer_public_jwk",
 "v_key_sha,p_attestation_sha",
 "issuer.public_jwk",
 "issuer.revoked_at IS NOT NULL"
 ]) assert.ok(sql.includes(x),"missing "+x);
});
test("old v2 service path retired; v3 restricted to service role, not clients",()=>{
 assert.match(sql,/REVOKE ALL ON FUNCTION public\.bl20_recovery_v1_review_consume_v2\(\s*uuid,uuid,uuid,text,text,text\) FROM PUBLIC,anon,authenticated,service_role/);
 assert.match(sql,/GRANT EXECUTE ON FUNCTION public\.bl20_recovery_v1_review_consume_v3\(\s*uuid,uuid,uuid,text,text,text\) TO service_role/);
 assert.match(sql,/REVOKE ALL ON FUNCTION public\.bl20_recovery_v1_review_consume_v3\(\s*uuid,uuid,uuid,text,text,text\) FROM PUBLIC,anon,authenticated/);
});
test("historical issuer pin and audit cannot be updated or deleted normally",()=>{
 assert.match(sql,/CREATE TRIGGER receipt_pin_immutable\s+BEFORE UPDATE OR DELETE/);
 assert.match(sql,/CREATE TRIGGER issuer_event_immutable\s+BEFORE UPDATE OR DELETE/);
 assert.match(sql,/Issuer historical evidence is immutable/);
 assert.match(sql,/ENABLE ROW LEVEL SECURITY/g);
 assert.match(sql,/REVOKE ALL ON ALL TABLES IN SCHEMA bl20_issuer_pin_v1_private\s+FROM PUBLIC,anon,authenticated,service_role/);
});
test("governance staging requires pinned receipt and identical active signer key",()=>{
 assert.match(sql,/CREATE TRIGGER require_issuer_pin_for_governance\s+BEFORE INSERT ON bl20_first_device_v1_private.review_intents/);
 assert.match(sql,/issuer.public_jwk IS DISTINCT FROM pin.issuer_public_jwk/);
 assert.match(sql,/receipt.attestation_sha256<>pin.attestation_sha256/);
 assert.match(sql,/pin.issuer_public_key_sha256<>NEW.issuer_key_sha256/);
 assert.match(sql,/issuer.revoked_at IS NOT NULL/);
});
test("issuer key rotation, revocation and disable veto pending governance atomically",()=>{
 assert.match(sql,/CREATE TRIGGER issuer_key_rotation_and_revocation/);
 assert.match(sql,/event_kind IN \('key_rotated','issuer_revoked','issuer_disabled'\)/);
 assert.match(sql,/UPDATE bl20_first_device_v1_private.review_intents/);
 assert.match(sql,/state='governance_vetoed'/);
 assert.match(sql,/event_kind\)\s+VALUES\(intent.id,'intent_vetoed'\)/);
 assert.match(sql,/Revoked issuer cannot be automatically reactivated/);
});
test("staged Phase7H cannot itself create device trust or issuer credentials",()=>{
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+public\.messaging_devices/i);
 assert.doesNotMatch(sql,/\bUPDATE\s+public\.messaging_devices/i);
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+public\.messaging_device_signing_keys/i);
 assert.doesNotMatch(sql,/\bUPDATE\s+public\.messaging_device_signing_keys/i);
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+bl20_recovery_v1_private\.issuers/i);
 assert.doesNotMatch(sql,/bl20_commit_device_approval/);
 assert.match(sql,/'deviceApproved',false/);
 assert.match(sql,/'trustedDevice',false/);
 assert.match(sql,/'e2eeV2Ready',false/);
});
test("all live Edge feature gates remain hard disabled",()=>{
 assert.match(recovery,/const RECOVERY_RELEASED = false/);
 assert.match(candidate,/const FEATURE_RELEASED=false/);
 assert.match(approved,/const APPROVAL_FEATURE_RELEASED = false/);
 assert.match(approved2,/const V2_RELEASED=false/);
});
