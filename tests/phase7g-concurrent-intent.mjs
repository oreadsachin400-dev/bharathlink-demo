// Disposable Phase 7G PostgreSQL concurrency test. NEVER a live Supabase test.
import assert from "node:assert/strict";
import {execFileSync,spawn} from "node:child_process";
const USER="99999999-9999-4999-8999-999999999999";
const SESSION="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const pg=sql=>execFileSync("psql",["-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
  {encoding:"utf8",stdio:["ignore","pipe","pipe"]}).trim();
const attempt=sql=>new Promise(resolve=>{
 const p=spawn("psql",["-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
   {stdio:["ignore","pipe","pipe"]});
 let out="",err="";
 p.stdout.on("data",d=>out+=d.toString());
 p.stderr.on("data",d=>err+=d.toString());
 p.on("error",e=>resolve({ok:false,err:String(e)}));
 p.on("close",code=>resolve({ok:code===0,out:out.trim(),err:err.trim()}));
});
const challenge=pg("SELECT challenge_id::text FROM bl20_recovery_v1_private.receipts "+
 "WHERE user_id='"+USER+"'::uuid LIMIT 1;");
assert.match(challenge,/^[0-9a-f-]{36}$/);
const sql="SELECT bl20_first_device_v1_private.stage_review_intent("+
 "'"+USER+"'::uuid,'"+SESSION+"'::uuid,'"+challenge+"'::uuid)::text;";
const baseline=Number(pg("SELECT count(*) FROM public.messaging_devices;"));
const [a,b]=await Promise.all([attempt(sql),attempt(sql)]);
assert.equal([a,b].filter(x=>x.ok).length,1,
 "exactly one first-device governance intent can be staged");
assert.equal([a,b].filter(x=>!x.ok).length,1,
 "duplicate concurrency must be rejected");
const receipt=JSON.parse([a,b].find(x=>x.ok).out);
assert.equal(receipt.governancePending,true);
assert.equal(receipt.independentAuthorityVerified,false);
assert.equal(receipt.deviceApproved,false);
assert.equal(receipt.trustedDevice,false);
assert.equal(receipt.e2eeV2Ready,false);
const repeat=await attempt(sql);
assert.equal(repeat.ok,false,"late replay must be rejected");
assert.equal(pg("SELECT count(*) FROM bl20_first_device_v1_private.review_intents;"),"1");
assert.equal(pg("SELECT count(*) FROM bl20_first_device_v1_private.audit_events WHERE event_kind='intent_staged';"),"1");
assert.equal(Number(pg("SELECT count(*) FROM public.messaging_devices;")),baseline);
const subject=pg("SELECT state FROM bl20_first_device_v1_private.review_intents LIMIT 1");
assert.equal(subject,"governance_pending_review_only");
console.log("PASS: Phase7G one-time pending governance intent, replay rejected; ZERO device trust");
