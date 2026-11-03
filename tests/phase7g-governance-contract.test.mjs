import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const root=new URL("../",import.meta.url);
const read=p=>readFileSync(new URL(p,root),"utf8");
const sql=read("sql/staged/TEST-first-device-governance-intent-v1.sql");
const candidate=read("supabase/functions/bl20-candidate-possession/index.ts");
const approval=read("supabase/functions/bl20-device-approval/index.ts");
const approvalV2=read("supabase/functions/bl20-device-approval-v2/index.ts");
const recovery=read("supabase/functions/bl20-recovery-v1/index.ts");
test("no trust transition exists in Phase7G governance SQL",()=>{
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+public\.messaging_devices/i);
 assert.doesNotMatch(sql,/\bUPDATE\s+public\.messaging_devices/i);
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+public\.messaging_device_signing_keys/i);
 assert.doesNotMatch(sql,/\bUPDATE\s+public\.messaging_device_signing_keys/i);
 assert.doesNotMatch(sql,/register_e2ee_v2_device\s*\(/i);
 assert.doesNotMatch(sql,/bl20_commit_device_approval\s*\(/i);
 assert.match(sql,/'deviceApproved',false/);
 assert.match(sql,/'trustedDevice',false/);
 assert.match(sql,/'e2eeV2Ready',false/);
 assert.match(sql,/'independentAuthorityVerified',false/);
});
test("private SQL governance is invoker-only and not exposed to apps",()=>{
 assert.match(sql,/CREATE SCHEMA bl20_first_device_v1_private/);
 assert.match(sql,/SECURITY INVOKER/);
 assert.doesNotMatch(sql,/SECURITY DEFINER/);
 assert.match(sql,/REVOKE ALL ON SCHEMA bl20_first_device_v1_private\s+FROM PUBLIC,anon,authenticated,service_role/);
 assert.match(sql,/REVOKE ALL ON FUNCTION bl20_first_device_v1_private\.stage_review_intent\(uuid,uuid,uuid\)\s+FROM PUBLIC,anon,authenticated,service_role/);
 assert.match(sql,/REVOKE ALL ON FUNCTION bl20_first_device_v1_private\.veto_review_intent\(uuid,text\)\s+FROM PUBLIC,anon,authenticated,service_role/);
 assert.doesNotMatch(sql,/GRANT\s+(?:USAGE|EXECUTE)\b/i);
});
test("governance requires previously consumed independent receipt and exact key binding",()=>{
 for(const needle of [
   "c.state<>'review_consumed'","rr.case_id","rr.payload_sha256",
   "rr.attestation_sha256","candidate.state<>'possession_proven'",
   "request.proposed_public_key_jwk IS DISTINCT FROM candidate.ecdh_public_jwk",
   "request.proposed_signing_public_key_jwk IS DISTINCT FROM candidate.signing_public_jwk",
   "request.approval_protocol_version IS DISTINCT FROM 3",
   "issuer.revoked_at IS NOT NULL","issuer.independently_approved",
   "rc.reviewer_a=rc.reviewer_b","rc.consent_at<c.created_at",
   "c.expires_at<=v_now","auth.sessions"
 ])assert.ok(sql.includes(needle),"Missing "+needle);
});
test("governance record is non-approving and supports audited one-way veto",()=>{
 assert.match(sql,/CHECK\(state IN \('governance_pending_review_only','governance_vetoed'\)\)/);
 assert.match(sql,/CHECK\(event_kind IN \('intent_staged','intent_vetoed'\)\)/);
 assert.match(sql,/UNIQUE\s+REFERENCES bl20_recovery_v1_private\.cases/);
 assert.match(sql,/CHECK\(reviewer_a<>reviewer_b/);
 assert.match(sql,/WITH CHECK|CHECK\(/);
 assert.match(sql,/state='governance_vetoed'/);
});
test("old Edge release gates must stay hard disabled",()=>{
 assert.match(candidate,/const FEATURE_RELEASED=false;/);
 assert.match(approval,/const APPROVAL_FEATURE_RELEASED = false;/);
 assert.match(approvalV2,/const V2_RELEASED=false;/);
 assert.match(recovery,/const RECOVERY_RELEASED = false;/);
});
test("governance never creates a real issuer or an operator bypass",()=>{
 assert.doesNotMatch(sql,/\bINSERT\s+INTO\s+bl20_recovery_v1_private\.issuers/i);
 assert.doesNotMatch(sql,/GOOGLE_PLAY_PROTECT_ALLOWED|skipIdentityCheck|forceTrusted/i);
 assert.doesNotMatch(sql,/CREATE OR REPLACE FUNCTION public\./i);
});
