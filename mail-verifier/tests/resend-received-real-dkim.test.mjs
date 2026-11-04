import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {verifyResendReceivedDkim,resolveTrustedDkimTxt,decodeDohTxt} from
  "../verify-resend-received-dkim.mjs";

const ID="received-email-001";
const FROM="Bank Support <alerts@bank.example>";
const TO="reader@bharathlink.com";
const KEY="re_synthetic_key_not_used_outside_tests";
const HOST="signed-raw.example.test";
const now=new Date("2026-11-04T08:02:00.000Z");
const kp=generateKeyPairSync("rsa",{modulusLength:2048,publicExponent:0x10001});
const pub=kp.publicKey.export({format:"der",type:"spki"}).toString("base64");
const txt="v=DKIM1; k=rsa; p="+pub;
const plain=[
 "From: "+FROM,"To: "+TO,"Subject: Your statement",
 "Date: Wed, 04 Nov 2026 08:00:00 +0000",
 "Message-ID: <synthetic-resend-mail@bank.example>",
 "MIME-Version: 1.0","Content-Type: text/plain; charset=utf-8",
 "","","This is a harmless synthetic test body."
].join("\r\n");
async function signedMessage(){
 const sign=await dkimSign(Buffer.from(plain),{
  canonicalization:"relaxed/relaxed",
  algorithm:"rsa-sha256",strict:true,
  signTime:new Date("2026-11-04T08:00:00Z"),
  signatureData:[{
   signingDomain:"bank.example",selector:"key1",
   privateKey:kp.privateKey.export({format:"pem",type:"pkcs8"})
  }]
 });
 assert.equal(sign.errors.length,0);
 return Buffer.from(sign.signatures+plain);
}
function fakeApi(raw,{from=FROM,to=[TO],id=ID,
 dnsRecord=txt,headers={},rawUrl="https://"+HOST+"/raw?id=synthetic"
}={}){
 const calls=[];
 const fetchFn=async(url,init)=>{
  calls.push({url:String(url),init});
  if(String(url).startsWith("https://api.resend.com/emails/receiving/")){
   return Response.json({
    id,from,to,
    headers:{"Authentication-Results":"attacker.example; dkim=pass; spf=pass; dmarc=pass",...headers},
    raw:{download_url:rawUrl,expires_at:new Date(Date.now()+600000).toISOString()}
   });
  }
  if(String(url).startsWith("https://"+HOST+"/")){
   assert.equal(init.headers.Authorization,undefined);
   return new Response(raw,{status:200,headers:{"Content-Type":"message/rfc822"}});
  }
  if(String(url).startsWith("https://cloudflare-dns.com/dns-query?")){
   const name=new URL(String(url)).searchParams.get("name");
   assert.equal(name,"key1._domainkey.bank.example");
   assert.equal(init.redirect,"manual");
   return Response.json({Status:0,Answer:[{
    type:16,name:name+".",data:JSON.stringify(dnsRecord)
   }]});
  }
  throw Error("Unexpected network request");
 };
 return {calls,fetchFn};
}
const options={provider_email_id:ID,from_address:FROM,recipient_address:TO,
 resendApiKey:KEY,allowedRawHosts:HOST,now};
test("signed real MIME bytes from Resend API and independently queried public DKIM key authenticate domain only",async()=>{
 const f=fakeApi(await signedMessage());
 const r=await verifyResendReceivedDkim({...options,fetchFn:f.fetchFn});
 assert.equal(r.dkim,"pass");
 assert.equal(r.signature_domain,"bank.example");
 assert.equal(r.domain_signature_verified,true);
 assert.equal(r.spf,"not_checked");
 assert.equal(r.dmarc,"not_checked");
 assert.equal(r.sender_identity,"not_verified");
 assert.equal(r.organization_authority,"not_verified");
 assert.equal(r.payment_request,"not_verified");
 assert.equal(r.is_sender_verified,false);
 assert.equal(r.is_safe,false);
 assert.equal(r.is_fake_proven,false);
 assert.equal(r.test_only,true);
 assert.equal(f.calls.length,3);
 assert.ok(Object.isFrozen(r));
});
test("unsigned MIME with forged Authentication-Results never passes",async()=>{
 const raw=Buffer.from("Authentication-Results: attacker.example; dkim=pass\r\n"+plain);
 const f=fakeApi(raw);
 const r=await verifyResendReceivedDkim({...options,fetchFn:f.fetchFn});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.domain_signature_verified,false);
});
test("tampered signed MIME is no longer authenticated",async()=>{
 const signed=await signedMessage();
 const tampered=Buffer.from(signed.toString().replace("harmless","malicious"));
 const f=fakeApi(tampered);
 const r=await verifyResendReceivedDkim({...options,fetchFn:f.fetchFn});
 assert.notEqual(r.dkim,"pass");
});
test("wrong DNS key cannot verify signature",async()=>{
 const signed=await signedMessage();
 const other=generateKeyPairSync("rsa",{modulusLength:2048});
 const wrong="v=DKIM1; k=rsa; p="+other.publicKey.export({format:"der",type:"spki"}).toString("base64");
 const f=fakeApi(signed,{dnsRecord:wrong});
 const r=await verifyResendReceivedDkim({...options,fetchFn:f.fetchFn});
 assert.equal(r.domain_signature_verified,false);
});
test("Resend account mismatch is denied before any raw URL or DNS lookup",async()=>{
 const fake=fakeApi(await signedMessage(),{from:"Someone <other@bank.example>"});
 await assert.rejects(verifyResendReceivedDkim({...options,fetchFn:fake.fetchFn}),
  /provider_message_binding_failed/);
 assert.equal(fake.calls.length,1);
});
test("allowlisted raw host cannot be redirected to attacker or private network",async()=>{
 const fake=fakeApi(await signedMessage(),{rawUrl:"https://127.0.0.1/secret"});
 await assert.rejects(verifyResendReceivedDkim({...options,fetchFn:fake.fetchFn}),
  /untrusted_signed_raw_origin/);
 assert.equal(fake.calls.length,1);
});
test("DNS-over-HTTPS only queries exact public resolver and DKIM TXT names",async()=>{
 const fake=fakeApi(await signedMessage());
 assert.deepEqual(await resolveTrustedDkimTxt("key1._domainkey.bank.example","TXT",
  {fetchFn:fake.fetchFn}),[[txt]]);
 assert.equal(fake.calls.length,1);
 assert.match(fake.calls[0].url,/^https:\/\/cloudflare-dns.com\/dns-query\?/);
 for(const q of ["localhost","169.254.169.254","key1.example.com",
   "key1._domainkey.bank.example?name=evil.example"])
  await assert.rejects(resolveTrustedDkimTxt(q,"TXT",{fetchFn:fake.fetchFn}),
   /dns_query_not_dkim/);
 assert.equal(fake.calls.length,1);
});
test("malformed and split TXT segments decode only when unambiguous",()=>{
 assert.equal(decodeDohTxt('"abc" "def"'),"abcdef");
 for(const value of ["unquoted","",'"no-close','"abc" trailing','"a"'.repeat(18)]){
  assert.throws(()=>decodeDohTxt(value),/dns_invalid_txt/);
 }
});
test("multiple contradictory DNS TXT records fail closed",async()=>{
 const fake={
  fetchFn:async()=>Response.json({Status:0,Answer:[
   {type:16,name:"key1._domainkey.bank.example.",data:JSON.stringify(txt)},
   {type:16,name:"key1._domainkey.bank.example.",data:JSON.stringify("v=DKIM1; p=evil")}
  ]})
 };
 await assert.rejects(resolveTrustedDkimTxt("key1._domainkey.bank.example","TXT",fake),
  /dns_missing_or_ambiguous_txt/);
});
test("no secret or raw host authorization => no Resend call",async()=>{
 let attempts=0;
 const fetchFn=()=>{attempts++;throw Error("not allowed");};
 await assert.rejects(verifyResendReceivedDkim({...options,resendApiKey:"",
   fetchFn}),/resend_verifier_not_configured/);
 await assert.rejects(verifyResendReceivedDkim({...options,allowedRawHosts:"",
   fetchFn}),/resend_verifier_not_configured/);
 assert.equal(attempts,0);
});
test("DNS network outage results in not checked, never a false pass",async()=>{
 const signed=await signedMessage();
 const f=fakeApi(signed);
 const r=await verifyResendReceivedDkim({...options,fetchFn:f.fetchFn,
  resolveTxt:async()=>{throw Error("public DNS outage");}});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.domain_signature_verified,false);
 assert.equal(r.is_sender_verified,false);
});
