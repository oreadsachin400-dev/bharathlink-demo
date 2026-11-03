import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const read=p=>readFileSync(new URL(p,import.meta.url),"utf8");
const sql=read("../sql/staged/TEST-device-approval-v2-candidate-possession-gate.sql");
const edge=read("../supabase/functions/bl20-device-approval/index.ts");
const candidateEdge=read("../supabase/functions/bl20-candidate-possession/index.ts");
const recovery=read("../supabase/functions/bl20-recovery-v1/index.ts");
test("legacy v1 commit is withdrawn from service role in STAGED v2",()=>{
  assert.match(sql,/REVOKE ALL ON FUNCTION public\.bl20_commit_device_approval\(\s*uuid,uuid,uuid,text,text\) FROM PUBLIC,anon,authenticated,service_role/);
  assert.match(sql,/GRANT EXECUTE ON FUNCTION public\.bl20_commit_device_approval_v2\(/);
  assert.match(sql,/TO service_role/);
});
test("v2 requires signed candidate proof state bound to both keys",()=>{
 for(const required of [
  "p_candidate_proof_id","p.state<>'possession_proven'",
  "p.ecdh_public_jwk IS DISTINCT FROM r.proposed_public_key_jwk",
  "p.signing_public_jwk IS DISTINCT FROM r.proposed_signing_public_key_jwk",
  "p.device_id<>r.proposed_device_id","AND user_id=p_user_id FOR UPDATE",
  "p.consumed_at IS NULL"
 ])assert.ok(sql.includes(required),required);
});
test("v2 cannot downgrade to approval protocol 1 or reuse proof",()=>{
  assert.match(sql,/r\.approval_protocol_version IS DISTINCT FROM 2/);
  assert.match(sql,/proof_id uuid PRIMARY KEY/);
  assert.match(sql,/request_id uuid NOT NULL UNIQUE/);
  assert.match(sql,/device_id uuid NOT NULL UNIQUE/);
  assert.match(sql,/FOR UPDATE/);
  assert.match(sql,/candidateProofBound',true/);
});
test("v2 only calls existing trusted-approver commit after possession checks",()=>{
  const candidate=sql.indexOf("p.state<>'possession_proven'");
  const legacy=sql.indexOf("result:=public.bl20_commit_device_approval");
  assert.ok(candidate>0 && legacy>candidate);
  assert.ok(sql.includes("p_payload_digest,p_signing_key_digest"));
});
test("proof-to-device link table remains private/RLS and no direct user grants",()=>{
  assert.match(sql,/ALTER TABLE bl20_candidate_v1_private\.trusted_approval_links ENABLE ROW LEVEL SECURITY/);
  assert.match(sql,/REVOKE ALL ON TABLE bl20_candidate_v1_private\.trusted_approval_links\s+FROM PUBLIC,anon,authenticated,service_role/);
  assert.ok(!/GRANT\s+(INSERT|UPDATE)\s+ON\s+public\.messaging_devices/i.test(sql));
});
test("approval Edge hard-disabled and still uses v1; staging NOT deployed",()=>{
  assert.match(edge,/const APPROVAL_FEATURE_RELEASED = false/);
  assert.match(edge,/BHARATHLINK_DEVICE_APPROVAL_ENABLED/);
  assert.match(edge,/bl20_commit_device_approval"/);
  assert.match(candidateEdge,/const FEATURE_RELEASED=false/);
  assert.match(recovery,/const RECOVERY_RELEASED = false/);
  assert.ok(!sql.includes("DROP POLICY"));
});
test("first-device trust transition has no public or active bridge",()=>{
  assert.ok(!/CREATE OR REPLACE FUNCTION public\.bl20_first_device_approve/i.test(sql));
  assert.ok(!/insert into public\.messaging_devices/i.test(recovery));
  assert.match(sql,/p_approver_device_id/);
  assert.match(sql,/public\.bl20_commit_device_approval\(/);
});
test("candidate proof freshness and replay are explicit",()=>{
  assert.match(sql,/p.created_at<v_now-interval '15 minutes'/);
  assert.match(sql,/p.consumed_at<p.created_at/);
  assert.match(sql,/p.consumed_at>v_now/);
  assert.match(sql,/trusted_approval_links\s+WHERE proof_id=p.id/);
});
