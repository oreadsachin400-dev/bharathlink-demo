import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto,randomUUID} from "node:crypto";
import {readFileSync,mkdtempSync,writeFileSync,copyFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath,pathToFileURL} from "node:url";
import {validateReport,payload,verifySignedReport} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const here=fileURLToPath(new URL("../supabase/functions/bl-mail-auth-attest/",import.meta.url));
const source=readFileSync(join(here,"index.ts"),"utf8");
const REPORT_URL="https://mail-auth.synthetic.invalid";
const SERVICE="only-disposable-synthetic-service-token";
const KID="independent-smtp-audit-key-v1";
const NOW=Math.floor(Date.now()/1000);
// Node 22 provides read-only globalThis.crypto; do not overwrite it.

function report(overrides={}){
 return {
   v:1,aud:"bharathlink-mail-auth-v1",kid:KID,
   provider_email_id:"mail-a-01",
   from_address:"Bank Support <alerts@bank.example>",
   recipient_address:"reply+a0000000-0000-4000-8000-000000000001@bharathlink.com",
   sender_domain:"bank.example",
   spf:"pass",spf_domain:"bank.example",
   dkim:"pass",dkim_domain:"bank.example",
   dmarc:"pass",nonce:randomUUID(),
   issued_at:NOW,expires_at:NOW+90,...overrides
 };
}
async function pair(){
 const keys=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const p=await crypto.subtle.exportKey("jwk",keys.publicKey);
 return {privateKey:keys.privateKey,publicJwk:{kty:"EC",crv:"P-256",x:p.x,y:p.y}};
}
async function envelope(r,key){
 const sig=new Uint8Array(await crypto.subtle.sign(
   {name:"ECDSA",hash:"SHA-256"},key.privateKey,new TextEncoder().encode(payload(r))));
 return {report:r,signature:Buffer.from(sig).toString("base64url")};
}
test("real P-256 signature from independent test issuer binds full provider/sender/recipient and all three protocol statuses",async()=>{
 const key=await pair();
 const r=report();
 const e=await envelope(r,key);
 const verified=await verifySignedReport(e,key.publicJwk,KID,NOW);
 assert.equal(verified.from_address,r.from_address);
 assert.equal(verified.recipient_address,r.recipient_address);
 assert.equal(verified.spf,"pass");
 assert.equal(verified.dkim,"pass");
 assert.equal(verified.dmarc,"pass");
 assert.match(verified.report_sha256,/^[0-9a-f]{64}$/);
 assert.notEqual(verified.report_sha256,"0".repeat(64));
});
test("forged unsigned Authentication-Results cannot become domain-verified",async()=>{
 const keys=await pair();const e=await envelope(report(),keys);
 const forged={...e,report:{...e.report,dmarc:"fail",from_address:"Fake <fake@example.org>",recipient_address:"other@example.com"}};
 await assert.rejects(verifySignedReport(forged,keys.publicJwk,KID,NOW),/from_domain_mismatch|invalid_signature/);
 const extra={...e,headers:{"Authentication-Results":"receiver; dmarc=pass"}};
 await assert.rejects(verifySignedReport(extra,keys.publicJwk,KID,NOW),/bad_envelope/);
});
test("two independent signing keys cannot impersonate each other",async()=>{
 const honest=await pair(),attacker=await pair();
 const e=await envelope(report(),attacker);
 await assert.rejects(verifySignedReport(e,honest.publicJwk,KID,NOW),/invalid_signature/);
});
test("key-id and recipient binding cannot be changed after signing",async()=>{
 const k=await pair();const e=await envelope(report(),k);
 await assert.rejects(verifySignedReport(e,k.publicJwk,"wrong-kid",NOW),/unexpected_issuer_key/);
 await assert.rejects(verifySignedReport({...e,report:{...e.report,recipient_address:"fraud@example.com"}},k.publicJwk,KID,NOW),/invalid_signature/);
});
test("reject signed DMARC pass lacking independently asserted exact SPF/DKIM domain alignment",async()=>{
 for(const item of [
   {spf:"pass",spf_domain:"evil.example",dkim:"fail",dkim_domain:"bank.example",dmarc:"pass"},
   {spf:"none",spf_domain:"",dkim:"pass",dkim_domain:"attacker.example",dmarc:"pass"},
   {spf:"none",spf_domain:"",dkim:"none",dkim_domain:"",dmarc:"pass"}
 ]){
   assert.throws(()=>validateReport(report(item),NOW),/unproven_strict_alignment/);
 }
});
test("properly signed domain with exact-aligned DKIM may pass despite SPF fail",async()=>{
 const key=await pair();const r=report({spf:"fail",spf_domain:"",dkim:"pass",dkim_domain:"bank.example",dmarc:"pass"});
 const v=await verifySignedReport(await envelope(r,key),key.publicJwk,KID,NOW);
 assert.equal(v.dmarc,"pass");
});
test("do not infer relaxed domain alignment via naïve last-two-label test",()=>{
 assert.throws(()=>validateReport(report({spf:"pass",spf_domain:"bank.co.uk",dkim:"none",dkim_domain:"",sender_domain:"alerts.bank.co.uk",from_address:"x@alerts.bank.co.uk"}),NOW),/unproven_strict_alignment/);
});
test("expiry, old and future reports are denied before signature check",()=>{
 assert.throws(()=>validateReport(report({issued_at:NOW-121,expires_at:NOW+1}),NOW),/stale_or_future/);
 assert.throws(()=>validateReport(report({issued_at:NOW+31,expires_at:NOW+100}),NOW),/stale_or_future/);
 assert.throws(()=>validateReport(report({issued_at:NOW-91,expires_at:NOW-1}),NOW),/expired_report/);
 assert.throws(()=>validateReport(report({expires_at:NOW+190}),NOW),/expired_report/);
});
test("ambiguous From, header injection, invalid/Unicode addresses and extra unknown fields are denied",()=>{
 for(const from of [
   "Alice <a@example.com>, Bob <b@example.com>",
   "Alice <a@example.com>\r\nAuthentication-Results: trusted; dmarc=pass",
   "A <a@example.com> <b@example.com>",
   "a@@example.com","a@éxample.com","no-address"
 ])assert.throws(()=>validateReport(report({from_address:from}),NOW),/invalid_from|ambiguous_from/);
 assert.throws(()=>validateReport(report({spoofed_verified:true}),NOW),/schema_mismatch/);
});
test("untrusted signer key material not accepted as verifier public key",async()=>{
 const e=await envelope(report(),await pair());
 for(const bad of [null,{}, {kty:"oct",k:"abcd"}, {kty:"EC",crv:"secp256k1",x:"a".repeat(43),y:"b".repeat(43)}])
   await assert.rejects(verifySignedReport(e,bad,KID,NOW),/invalid_public_key/);
});
test("bounded signature encoding and P256 signature size enforced",async()=>{
 const keys=await pair(),e=await envelope(report(),keys);
 await assert.rejects(verifySignedReport({...e,signature:"A"},keys.publicJwk,KID,NOW),/wrong_signature_size/);
 await assert.rejects(verifySignedReport({...e,signature:"-".repeat(2000)},keys.publicJwk,KID,NOW),/bad_signature_encoding/);
});
test("hard-disabled Edge source cannot be enabled by environment or request flag",()=>{
 assert.match(source,/const MAIL_AUTH_RELEASED=false; \/\/ hard HOLD/);
 assert.doesNotMatch(source,/MAIL_AUTH_RELEASED\s*=\s*Deno\.env/);
 assert.match(source,/if\(!MAIL_AUTH_RELEASED\)return json\(503/);
 assert.match(source,/verifySignedReport/);
 assert.match(source,/bl_mail_record_auth_attestation_v1/);
});
test("staged Edge handler rejects all calls before reading secrets or contacting HTTP",async()=>{
 const tmp=mkdtempSync(join(tmpdir(),"blmail-auth-off-"));
 const oldDeno=globalThis.Deno,oldFetch=globalThis.fetch;
 let handler;
 try{
   copyFileSync(join(here,"signed-report.mjs"),join(tmp,"signed-report.mjs"));
   const js=source.replace("(status:number,body:unknown)","(status,body)").replace("async(req:Request)=>","async(req)=>");
   writeFileSync(join(tmp,"index.mjs"),js);
   let touched=0;
   globalThis.Deno={env:{get(){touched++;throw Error("never touch production env");}},serve(fn){handler=fn;}};
   globalThis.fetch=async()=>{touched++;throw Error("network must remain off");};
   await import(pathToFileURL(join(tmp,"index.mjs")).href);
   const res=await handler(new Request(REPORT_URL+"/functions/v1/bl-mail-auth-attest",{method:"POST",body:"{}"}));
   assert.equal(res.status,503);
   assert.equal((await res.json()).error,"independent_verifier_not_approved");
   assert.equal(touched,0);
 }finally{globalThis.Deno=oldDeno;globalThis.fetch=oldFetch;rmSync(tmp,{recursive:true,force:true});}
});
test("synthetic enabled copy only: signed report is bound to service-only RPC, spoofed report denied before DB",async()=>{
 const tmp=mkdtempSync(join(tmpdir(),"blmail-auth-on-"));
 const oldDeno=globalThis.Deno,oldFetch=globalThis.fetch;
 const key=await pair();let handler,invocations=0;
 try{
   copyFileSync(join(here,"signed-report.mjs"),join(tmp,"signed-report.mjs"));
   const js=source.replace("const MAIL_AUTH_RELEASED=false;","const MAIL_AUTH_RELEASED=true;")
     .replace("(status:number,body:unknown)","(status,body)").replace("async(req:Request)=>","async(req)=>");
   assert.ok(js.includes("const MAIL_AUTH_RELEASED=true;"));
   writeFileSync(join(tmp,"index.mjs"),js);
   globalThis.Deno={env:{get(n){return {
     SUPABASE_URL:REPORT_URL,SUPABASE_SERVICE_ROLE_KEY:SERVICE,
     BL_MAIL_AUTH_VERIFIER_KEY_ID:KID,
     BL_MAIL_AUTH_VERIFIER_P256_PUBLIC_JWK:JSON.stringify(key.publicJwk)
   }[n];}},serve(fn){handler=fn;}};
   globalThis.fetch=async(url,opts)=>{
     invocations++;
     assert.equal(url,REPORT_URL+"/rest/v1/rpc/bl_mail_record_auth_attestation_v1");
     assert.equal(opts.headers.apikey,SERVICE);
     const b=JSON.parse(opts.body);
     assert.equal(b.p_provider_email_id,"mail-a-01");
     assert.equal(b.p_recipient_address,"reply+a0000000-0000-4000-8000-000000000001@bharathlink.com");
     assert.equal(b.p_dmarc,"pass");
     assert.match(b.p_sha256,/^[0-9a-f]{64}$/);
     return Response.json("recorded");
   };
   await import(pathToFileURL(join(tmp,"index.mjs")).href);
   const r=report(),e=await envelope(r,key);
   const make=v=>new Request(REPORT_URL+"/functions/v1/bl-mail-auth-attest",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(v)});
   const forged=await handler(make({...e,report:{...r,spf:"fail",dkim:"fail",dmarc:"fail"}}));
   assert.equal(forged.status,401);
   assert.equal(invocations,0);
   const valid=await handler(make(e));
   assert.equal(valid.status,200,await valid.text().catch(()=>"<body consumed>"));
   assert.equal(invocations,1);
 }finally{globalThis.Deno=oldDeno;globalThis.fetch=oldFetch;rmSync(tmp,{recursive:true,force:true});}
});
test("staged SQL and UI never convert local heuristics to verified identity",()=>{
 const sql=readFileSync(new URL("../sql/staged/TEST-bharatmail-signed-sender-auth-v1.sql",import.meta.url),"utf8");
 const ui=readFileSync(new URL("../index.html",import.meta.url),"utf8");
 assert.match(sql,/enable row level security/i);
 assert.match(sql,/recipient_user_id = \(select auth\.uid\(\)\)/);
 assert.match(sql,/security invoker/i);
 assert.match(sql,/revoke all on function public\.bl_mail_record_auth_attestation_v1/i);
 assert.match(sql,/not_routed_or_failed/);
 assert.match(sql,/conflicting_attestation/);
 assert.match(ui,/SPF\/DKIM\/DMARC: not checked/);
 assert.match(ui,/Not independently verified/);
});
