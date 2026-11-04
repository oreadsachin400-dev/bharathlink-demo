import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import worker from "../cloudflare-pilot-worker.mjs";
import {config,preflight,inspectAfterForward} from "../cloudflare-pilot-helpers.mjs";

const R="test-evidence@mail.test.bharathlink.example";
const S="reviewed-sink@receiver.example";
const ENV={
  BLMAIL_PILOT_MODE:"isolated-test-forwarding-only",
  BLMAIL_TEST_RECIPIENT:R,
  BLMAIL_TEST_SINK:S,
  BLMAIL_TEST_ZONE:"mail.test.bharathlink.example"
};
const MIME=Buffer.from([
 "From: Bank Notices <alerts@bank.example>",
 "To: "+R,
 "Reply-To: fraud@different.example",
 "Subject: Synthetic worker email",
 "Message-ID: <synthetic-001@bank.example>",
 "Authentication-Results: attacker.example; dmarc=pass",
 "",
 "No real sender was authenticated. SYNTHETIC ONLY.",
 ""
].join("\r\n"));
const A="mx.cloudflare.net; spf=pass smtp.mailfrom=bank.example; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example";
function message({
  to=R,from="bounce@bank.example",raw=MIME,rawSize=raw.length,
  authenticationResults=A,canBeForwarded=true,
  overrideHeaders={},forwardError=false
}={}){
 const attempts={forwarded:[],rejected:[],rawReads:0};
 const headers=new Headers({
   from:"Bank Notices <alerts@bank.example>",
   "reply-to":"fraud@different.example",
   "authentication-results":authenticationResults,
   ...overrideHeaders
 });
 const obj={
   from,to,headers,rawSize,canBeForwarded,
   raw:new ReadableStream({
     start(controller){
       controller.enqueue(new Uint8Array(raw));
       controller.close();
     }
   }),
   async forward(target){
     attempts.forwarded.push(target);
     if(forwardError)throw Error("synthetic failure never logs raw message");
   },
   setReject(reason){attempts.rejected.push(reason);},
   async reply(){throw Error("must not send reply");}
 };
 return {message:obj,attempts};
}
async function capture(fn){
 const oldInfo=console.info,oldWarn=console.warn;
 const lines=[];
 console.info=(...args)=>lines.push("INFO "+args.join(" "));
 console.warn=(...args)=>lines.push("WARN "+args.join(" "));
 try{await fn();}finally{console.info=oldInfo;console.warn=oldWarn;}
 return lines;
}

test("disabled-by-default Cloudflare email handler explicitly rejects without forwarding",async()=>{
 const f=message(),env={...ENV,BLMAIL_PILOT_MODE:"disabled"};
 const lines=await capture(()=>worker.email(f.message,env,{}));
 assert.equal(f.attempts.forwarded.length,0);
 assert.equal(f.attempts.rejected.length,1);
 assert.ok(lines.some(x=>x.includes("BLMAIL_TEST_REJECT:gated")));
});
test("exact test recipient and separate sink forward once, then observe without verified status",async()=>{
 const f=message();
 const lines=await capture(()=>worker.email(f.message,ENV,{}));
 assert.deepEqual(f.attempts.forwarded,[S]);
 assert.equal(f.attempts.rejected.length,0);
 assert.ok(lines.some(x=>x.includes("BLMAIL_TEST_FORWARD_OK_NO_SENDER_VERIFICATION")));
 const found=lines.find(x=>x.includes("BLMAIL_TEST_OBSERVATION {"));
 assert.ok(found);
 assert.match(found,/"spf_observation":"pass"/);
 assert.match(found,/"dkim_observation":"pass"/);
 assert.match(found,/"dmarc_observation":"pass"/);
 assert.match(found,/"issued_verified_sender":false/);
 assert.match(found,/"signed_report_generated":false/);
 // No email addresses, raw bytes or MIME fingerprints appear in logs.
 assert.ok(lines.every(x=>!x.includes("bank.example")&&!x.includes(R)&&
   !x.includes("synthetic-001")&&!x.includes("No real sender")&&
   !x.includes(createHash("sha256").update(MIME).digest("hex"))));
});
test("private raw MIME digest stays in memory and all sender trust remains HOLD",async()=>{
 const f=message();
 const observed=await inspectAfterForward(f.message);
 assert.equal(observed.raw_sha256,createHash("sha256").update(MIME).digest("hex"));
 assert.equal(observed.reply_to_mismatch_caution,true);
 assert.equal(observed.issued_verified_sender,false);
 assert.equal(observed.production_authorized,false);
 assert.equal(observed.signed_report_generated,false);
 assert.ok(Object.isFrozen(observed));
});
test("production apex or wrong-zone addresses are refused before forwarding",async()=>{
 for(const address of ["user@bharathlink.com","user@bharathlink.in","user@notatest.example"]){
  const f=message({to:address});
  const lines=await capture(()=>worker.email(f.message,{
    ...ENV,BLMAIL_TEST_RECIPIENT:address,
    BLMAIL_TEST_ZONE:address.split("@")[1]
  },{}));
  assert.deepEqual(f.attempts.forwarded,[]);
  assert.equal(f.attempts.rejected.length,1);
  assert.ok(lines.some(x=>x.includes("BLMAIL_TEST_REJECT:gated")));
 }
 const mismatched=message({to:"other@mail.test.bharathlink.example"});
 await capture(()=>worker.email(mismatched.message,ENV,{}));
 assert.equal(mismatched.attempts.forwarded.length,0);
 assert.equal(mismatched.attempts.rejected.length,1);
});
test("missing, looping or same-zone sink is rejected before forwarding",async()=>{
 for(const sink of ["","not-an-email",R,"attacker@mail.test.bharathlink.example"]){
  const f=message();
  await capture(()=>worker.email(f.message,{...ENV,BLMAIL_TEST_SINK:sink},{}));
  assert.equal(f.attempts.forwarded.length,0);
  assert.equal(f.attempts.rejected.length,1);
 }
});
test("worker must be explicitly configured with exact test domain pin",()=>{
 assert.throws(()=>config({...ENV,BLMAIL_TEST_ZONE:"wrong.test.example"}),/isolated_test_zone_not_pinned/);
 assert.throws(()=>config({...ENV,BLMAIL_PILOT_MODE:"production"}),/test_pilot_disabled/);
});
test("non-forwardable and oversized mail fails closed before delivery",async()=>{
 for(const f of [
  message({canBeForwarded:false}),
  message({rawSize:5*1024*1024+1}),
  message({rawSize:0})
 ]){
  await capture(()=>worker.email(f.message,ENV,{}));
  assert.equal(f.attempts.rejected.length,1);
  assert.equal(f.attempts.forwarded.length,0);
 }
});
test("failed forward triggers one reject and never calls reply or retry",async()=>{
 const f=message({forwardError:true});
 const lines=await capture(()=>worker.email(f.message,ENV,{}));
 assert.deepEqual(f.attempts.forwarded,[S]);
 assert.equal(f.attempts.rejected.length,1);
 assert.ok(lines.some(x=>x.includes("BLMAIL_TEST_REJECT:forward_failed")));
 assert.ok(lines.every(x=>!x.includes("synthetic failure")));
});
test("raw stream failure after successful forward does not retroactively reject delivered mail",async()=>{
 const f=message({rawSize:MIME.length+3});
 const lines=await capture(()=>worker.email(f.message,ENV,{}));
 assert.deepEqual(f.attempts.forwarded,[S]);
 assert.equal(f.attempts.rejected.length,0);
 assert.ok(lines.some(x=>x.includes("BLMAIL_TEST_OBSERVATION_NOT_AVAILABLE")));
 assert.ok(lines.every(x=>!x.includes("verified_sender:true")));
});
test("forged or ambiguous Authentication-Results never produces a verified assertion",async()=>{
 for(const result of [
  "attacker.example; spf=pass; dkim=pass; dmarc=pass",
  A+", attacker.example; dmarc=pass",
  "mx.cloudflare.net; spf=pass; dkim=pass; dkim=fail; dmarc=pass"
 ]){
  const f=message({authenticationResults:result});
  const lines=await capture(()=>worker.email(f.message,ENV,{}));
  assert.deepEqual(f.attempts.forwarded,[S]);
  const summary=lines.find(x=>x.includes("BLMAIL_TEST_OBSERVATION {"));
  assert.ok(summary);
  assert.match(summary,/"header_shape_valid":false/);
  assert.match(summary,/"spf_observation":"not_checked"/);
  assert.match(summary,/"issued_verified_sender":false/);
 }
});
test("real Worker handler shape exposes only email(message,env,ctx), never fetch route",()=>{
 assert.equal(typeof worker.email,"function");
 assert.equal(worker.fetch,undefined);
 assert.doesNotThrow(()=>preflight(message().message,ENV));
});
test("Cloudflare worker never directly calls outgoing fetch or sends emails",async()=>{
 const originalFetch=globalThis.fetch;
 let count=0;
 globalThis.fetch=()=>{count++;throw Error("must not fetch");};
 try{
  const f=message();
  await capture(()=>worker.email(f.message,ENV,{}));
  assert.equal(count,0);
 }finally{globalThis.fetch=originalFetch;}
});
