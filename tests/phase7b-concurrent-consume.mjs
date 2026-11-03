// Concurrency integration test against disposable localhost PostgreSQL ONLY.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";

function query(statement) {
  return new Promise(resolve=>{
    const p=spawn("psql",["-X","-q","-A","-t","-v","ON_ERROR_STOP=1",
      "-c",statement],{env:process.env});
    let out="",err="";
    p.stdout.on("data",c=>out+=c.toString());
    p.stderr.on("data",c=>err+=c.toString());
    p.on("error",e=>resolve({ok:false,out,err:String(e)}));
    p.on("close",code=>resolve({ok:code===0,out:out.trim(),err:err.trim()}));
  });
}
const uid="11111111-1111-4111-8111-111111111111";
const did="55555555-5555-4555-8555-555555555555";
const jwk=(x,y)=>
  "jsonb_build_object('kty','EC','crv','P-256','x',repeat('"+
  x+"',43),'y',repeat('"+y+"',43))";
const started=await query(
  "SELECT public.bl20_candidate_proof_start('"+uid+"','"+
  did+"',"+jwk("A","B")+","+jwk("C","D")+")->>'proofId';");
assert.equal(started.ok,true,started.err);
const id=started.out;
assert.match(id,/^[0-9a-f-]{36}$/);
const dig=await query("SELECT encode(extensions.digest(convert_to("+
 "(public.bl20_candidate_proof_context('"+uid+"','"+id+
 "')->>'payload'),'UTF8'),'sha256'),'hex');");
assert.equal(dig.ok,true,dig.err);
assert.match(dig.out,/^[0-9a-f]{64}$/);
const finish="SELECT public.bl20_candidate_proof_finish('"+uid+"','"+
  id+"','"+dig.out+"');";
const results=await Promise.all([query(finish),query(finish)]);
const success=results.filter(x=>x.ok).length;
const denied=results.filter(x=>!x.ok).length;
assert.equal(success,1,"exactly one consume must succeed");
assert.equal(denied,1,"other concurrent consume must be rejected");
assert.match(results.find(x=>x.ok).out,/"possessionProven": true/);
assert.match(results.find(x=>x.ok).out,/"serverApproved": false/);
const replay=await query(finish);
assert.equal(replay.ok,false,"late replay must be denied");
const ctx=await query("SELECT public.bl20_candidate_proof_context('"+
  uid+"','"+id+"') IS NULL;");
assert.equal(ctx.ok,true,ctx.err);
assert.equal(ctx.out,"t");
const devices=await query("SELECT count(*) FROM public.messaging_devices;");
assert.equal(devices.out,"0");
console.log("PASS: simultaneous consume exactly once, later replay denied, no devices added");
