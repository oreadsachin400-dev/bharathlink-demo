// Disposable PostgreSQL concurrency check of Phase7F v2 approval.
import assert from "node:assert/strict";
import {execFileSync,spawn} from "node:child_process";
const user="11111111-1111-4111-8111-111111111111";
const approver="22222222-2222-4222-8222-222222222222";
const rid="77777777-7777-4777-8777-777777777777";
const device="88888888-8888-4888-8888-888888888888";
const quote=s=>"'"+String(s).replaceAll("'","''")+"'";
const pg=sql=>execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
 {encoding:"utf8",stdio:["ignore","pipe","pipe"]}).trim();
const pgAsync=sql=>new Promise(resolve=>{
 const p=spawn("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
   {stdio:["ignore","pipe","pipe"]});
 let output="",err="";
 p.stdout.on("data",d=>output+=d);
 p.stderr.on("data",d=>err+=d);
 p.on("error",e=>resolve({ok:false,err:String(e)}));
 p.on("close",code=>resolve({ok:code===0,out:output.trim(),err:err.trim()}));
});
const key=(x,y)=>"jsonb_build_object('kty','EC','crv','P-256','x',repeat('"+x+"',43),'y',repeat('"+y+"',43))";
const dh=key("G","H"),sig=key("I","J");
pg("INSERT INTO public.messaging_device_enrollment_requests"+
 " (request_id,user_id,proposed_device_id,proposed_public_key_jwk,"+
 " proposed_signing_public_key_jwk,approval_protocol_version)"+
 " VALUES ("+quote(rid)+"::uuid,"+quote(user)+"::uuid,"+quote(device)+"::uuid,"+
 dh+","+sig+",2)");
const c=JSON.parse(pg("SELECT public.bl20_candidate_proof_start("+
 quote(user)+"::uuid,"+quote(device)+"::uuid,"+dh+","+sig+")::text;"));
const proof=c.proofId;
assert.match(proof,/^[0-9a-f-]{36}$/);
const payloadHash=pg("SELECT encode(extensions.digest("+
 "convert_to((public.bl20_candidate_proof_context("+
 quote(user)+"::uuid,"+quote(proof)+"::uuid)->>'payload'),'UTF8'),"+
 "'sha256'),'hex');");
const outcome=JSON.parse(pg("SELECT public.bl20_candidate_proof_finish("+
 quote(user)+"::uuid,"+quote(proof)+"::uuid,"+quote(payloadHash)+")::text;"));
assert.equal(outcome.possessionProven,true);
assert.equal(outcome.serverApproved,false);
const context=JSON.parse(pg("SELECT public.bl20_device_approval_context("+
 quote(user)+"::uuid,"+quote(rid)+"::uuid,"+quote(approver)+"::uuid)::text;"));
assert.equal(context.userId,user);
const signedPayloadHash=pg("SELECT encode(extensions.digest(convert_to("+
 quote(context.payload)+",'UTF8'),'sha256'),'hex');");
const command="SELECT public.bl20_commit_device_approval_v2("+
 [user,rid,approver,proof,signedPayloadHash,context.signingKeyDigest]
 .map((x,i)=>quote(x)+(i<4?"::uuid":"::text")).join(",")+")::text;";
const outcomes=await Promise.all([pgAsync(command),pgAsync(command)]);
assert.equal(outcomes.filter(x=>x.ok).length,1,
  "Exactly one concurrent trusted approver v2 commit");
assert.equal(outcomes.filter(x=>!x.ok).length,1,
  "Other concurrent v2 commit must be rejected");
const good=JSON.parse(outcomes.find(x=>x.ok).out);
assert.equal(good.approved,true);
assert.equal(good.candidateProofBound,true);
const tooLate=await pgAsync(command);
assert.equal(tooLate.ok,false,"Late replay must deny");
assert.equal(pg("SELECT count(*) FROM public.messaging_devices WHERE id="+quote(device)+"::uuid;"),"1");
assert.equal(pg("SELECT count(*) FROM bl20_candidate_v1_private.trusted_approval_links WHERE proof_id="+quote(proof)+"::uuid;"),"1");
assert.equal(pg("SELECT count(*) FROM public.messaging_device_signing_keys WHERE device_id="+quote(device)+"::uuid;"),"1");
console.log("PASS: Phase7F concurrent proof-gated approval exactly once; replay blocked and atomic link");
