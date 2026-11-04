import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {getBoundRawSha256,MAX_RAW_BYTES} from "../supabase/functions/bl-mail-auth-attest/resend-raw-evidence.mjs";

const ID="mail-test-001";
const FROM="Security <security@bank.example>";
const RECIPIENT="reply+abc123@bharathlink.com";
const RAW="From: Security <security@bank.example>\r\nTo: "+RECIPIENT+"\r\nAuthentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass\r\n\r\nHello!\r\n";
const DIGEST=createHash("sha256").update(RAW).digest("hex");
const KEY="re_offline_synthetic_private_key_not_real";
const HOST="raw.synthetic.invalid";
const opts={
 provider_email_id:ID,from_address:FROM,recipient_address:RECIPIENT,
 apiKey:KEY,allowedRawHosts:HOST
};
function makeMock({
 raw=RAW,from=FROM,to=[RECIPIENT],id=ID,
 url="https://"+HOST+"/r/original.eml?Signature=synthetic",
 expiresAt=new Date(Date.now()+600000).toISOString(),
 apiStatus=200,rawStatus=200,rawContentLength=null
}={}){
 const calls=[];
 const fetchFn=async (target,init)=>{
   calls.push({url:String(target),init});
   if(calls.length===1){
     assert.equal(String(target),"https://api.resend.com/emails/receiving/"+ID);
     assert.equal(init.headers.Authorization,"Bearer "+KEY);
     assert.equal(init.redirect,"manual");
     if(apiStatus!==200)return new Response("failed",{status:apiStatus});
     return Response.json({object:"email",id,from,to,
       headers:{"Authentication-Results":"injected; dmarc=pass"},
       raw:{download_url:url,expires_at:expiresAt}});
   }
   if(calls.length===2){
     // No Resend key, bearer or cookies sent to raw-content signed URL.
     assert.equal(init.headers.Authorization,undefined);
     assert.equal(init.redirect,"manual");
     if(rawStatus!==200)return new Response(null,{status:rawStatus});
     return new Response(raw,{status:200,headers:rawContentLength===null?{}:{"content-length":String(rawContentLength)}});
   }
   throw Error("unexpected request");
 };
 return {fetchFn,calls};
}
test("original raw message bytes are hashed without normalizing headers, and no user data uploaded",async()=>{
 const fake=makeMock();
 const proof=await getBoundRawSha256({...opts,fetchFn:fake.fetchFn});
 assert.equal(proof.raw_sha256,DIGEST);
 assert.equal(proof.provider_email_id,ID);
 assert.equal(proof.provenance,"resend-receiving-api-raw-content");
 for(const k of ["spf","dkim","dmarc"])assert.equal(proof[k],"not_checked");
 assert.equal(fake.calls.length,2);
 assert.equal(fake.calls[1].url,"https://"+HOST+"/r/original.eml?Signature=synthetic");
 assert.equal(Object.isFrozen(proof),true);
});
test("server-returned headers claiming SPF/DKIM/DMARC PASS cannot affect report or status",async()=>{
 const fake=makeMock({raw:RAW.replace("dmarc=pass","dmarc=fail")});
 const proof=await getBoundRawSha256({...opts,fetchFn:fake.fetchFn});
 assert.notEqual(proof.raw_sha256,DIGEST);
 assert.equal(proof.dmarc,"not_checked");
});
test("receiver metadata sender or recipient swaps are rejected before raw download",async()=>{
 for(const data of [
   {from:"Attacker <attacker@example.org>"},
   {to:["attacker@example.org"]},
   {to:[RECIPIENT,"attacker@example.org"]},
   {id:"another-id"}
 ]){
   const fake=makeMock(data);
   await assert.rejects(getBoundRawSha256({...opts,fetchFn:fake.fetchFn}),/provider_message_binding_failed/);
   assert.equal(fake.calls.length,1);
 }
});
test("signed raw URL requires operator-set exact HTTPS host, no redirects/SSRF",async()=>{
 for(const url of [
  "http://"+HOST+"/raw","https://127.0.0.1/raw","http://127.0.0.1/",
  "https://localhost/raw","https://"+HOST+".attacker.test/raw",
  "https://"+HOST+":8443/raw","https://username:password@"+HOST+"/raw",
  "https://evil.example/r","https://"+HOST+"/raw#secret",
  "file:///etc/passwd"
 ]){
   const fake=makeMock({url});
   await assert.rejects(getBoundRawSha256({...opts,fetchFn:fake.fetchFn}),/untrusted_signed_raw_origin/);
   assert.equal(fake.calls.length,1);
 }
});
test("provider redirects, raw redirects, and expired signed capabilities fail closed",async()=>{
 for(const cases of [
   {apiStatus:302},
   {rawStatus:302},
   {expiresAt:new Date(Date.now()-1000).toISOString()},
   {expiresAt:new Date(Date.now()+7200000).toISOString()}
 ]){
   const fake=makeMock(cases);
   await assert.rejects(getBoundRawSha256({...opts,fetchFn:fake.fetchFn}),
      /provider_read_failed|raw_download_failed|signed_raw_expired_or_unbounded/);
 }
});
test("overlarge raw MIME advertised size rejected before body read",async()=>{
 const fake=makeMock({rawContentLength:MAX_RAW_BYTES+1});
 await assert.rejects(getBoundRawSha256({...opts,fetchFn:fake.fetchFn}),/raw_size_exceeded/);
});
test("overlarge streamed raw MIME rejected even without Content-Length",async()=>{
 const huge=new Uint8Array(MAX_RAW_BYTES+1);
 huge.fill(65);
 const fake=makeMock({raw:huge});
 await assert.rejects(getBoundRawSha256({...opts,fetchFn:fake.fetchFn}),/raw_size_exceeded/);
});
test("allowlist cannot be inferred from signed URL, email domain, or an arbitrary request",async()=>{
 for(const hosts of ["","localhost","127.0.0.1","raw.synthetic.invalid,*.example.org","http://raw.synthetic.invalid"]){
  await assert.rejects(getBoundRawSha256({...opts,allowedRawHosts:hosts,fetchFn:makeMock().fetchFn}),
    /raw_hosts_not_configured/);
 }
});
test("raw source API key is mandatory and never accepts arbitrary non-Resend tokens",async()=>{
 for(const apiKey of ["",null,"s3_token","Bearer abc","re_short"]){
   await assert.rejects(getBoundRawSha256({...opts,apiKey,fetchFn:makeMock().fetchFn}),
      /missing_server_resend_key/);
 }
});
test("no user-input URL can replace the fixed Resend Receiving API origin",async()=>{
 const fake=makeMock();
 await assert.rejects(getBoundRawSha256({...opts,provider_email_id:"https://169.254.169.254/latest",fetchFn:fake.fetchFn}),/invalid_provider_id/);
 assert.equal(fake.calls.length,0);
});
test("forwarded user-controlled raw headers are evidence bytes, never authority",async()=>{
 const fake=makeMock({raw:"Authentication-Results: pretend; dmarc=pass\r\n\r\nMail body"});
 const proof=await getBoundRawSha256({...opts,fetchFn:fake.fetchFn});
 assert.equal(proof.spf,"not_checked");assert.equal(proof.dkim,"not_checked");
 assert.equal(proof.dmarc,"not_checked");
});
