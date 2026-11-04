import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {checkRealResendReceivedDkim} from "../check-resend-live-email.mjs";

const sender="Security Team <alerts@bank.example>";
const recipient="reader@example.net";
const id="synthetic-provider-001";
const signedHost="raw.synthetic.invalid";
const keypair=generateKeyPairSync("rsa",{modulusLength:2048,publicExponent:65537});
const publicTxt="v=DKIM1; k=rsa; p="+keypair.publicKey.export({format:"der",type:"spki"}).toString("base64");
const message=[
 "From: "+sender,
 "To: "+recipient,
 "Subject: Original signed test message",
 "Date: Wed, 04 Nov 2026 08:00:00 +0000",
 "Message-ID: <synthetic-1@bank.example>",
 "MIME-Version: 1.0",
 "Content-Type: text/plain; charset=utf-8",
 "",
 "This fixture is not a live received message.",
 ""
].join("\r\n");
async function signedMail(){
 const {signatures,errors}=await dkimSign(Buffer.from(message),{
  strict:true,algorithm:"rsa-sha256",canonicalization:"relaxed/relaxed",
  signTime:new Date("2026-11-04T08:00:00.000Z"),
  signatureData:[{signingDomain:"bank.example",selector:"key1",
    privateKey:keypair.privateKey.export({format:"pem",type:"pkcs8"})}]
 });
 assert.equal(errors.length,0);
 return signatures+message;
}
function fixture(raw,{from=sender,to=[recipient],host=signedHost}={}){
 const urls=[],rawURL="https://"+host+"/original.eml?sig=synthetic";
 const fetchFn=async(url,init)=>{
  urls.push({url:String(url),init});
  if(urls.length===1){
   assert.equal(String(url),"https://api.resend.com/emails/receiving/"+id);
   assert.equal(init.headers.Authorization,"Bearer re_synthetic_test_only_token");
   return Response.json({id,from,to,
     raw:{download_url:rawURL,expires_at:new Date(Date.now()+600000).toISOString()}});
  }
  if(urls.length===2){
   assert.equal(String(url),rawURL);
   assert.equal(init.headers.Authorization,undefined);
   return new Response(raw,{status:200});
  }
  throw Error("unexpected_external_request");
 };
 return {fetchFn,urls};
}
const now=new Date("2026-11-04T08:02:00.000Z");
const base={providerEmailId:id,fromAddress:sender,recipientAddress:recipient,
 apiKey:"re_synthetic_test_only_token",allowedRawHosts:signedHost,now};
const dns=async(name,type)=>{
 assert.equal(name,"key1._domainkey.bank.example");
 assert.equal(type,"TXT");
 return [[publicTxt]];
};
test("Resend provider-backed original bytes plus independent DNS can cryptographically validate an aligned DKIM domain",async()=>{
 const r=fixture(await signedMail());
 const result=await checkRealResendReceivedDkim({...base,fetchFn:r.fetchFn,resolveTxt:dns});
 assert.equal(result.dkim,"pass");
 assert.equal(result.dkim_strictly_aligned,true);
 assert.equal(result.outcome,"cryptographic_domain_signature_valid");
 assert.equal(result.original_mime_hash_matches_verifier,true);
 assert.equal(result.sender_verified_badge_allowed,false);
 assert.equal(result.human_sender_identity_verified,false);
 assert.equal(result.organization_authority_verified,false);
 assert.equal(result.payment_beneficiary_verified,false);
 assert.equal(result.spf,"not_checked");
 assert.equal(result.dmarc,"not_checked");
 assert.equal(r.urls.length,2);
 assert.ok(!JSON.stringify(result).includes("signedHost") &&
   !JSON.stringify(result).includes(id) &&
   !JSON.stringify(result).includes(recipient));
});
test("mail body changed in original MIME invalidates DKIM and never marks sender safe",async()=>{
 const raw=(await signedMail()).replace("not a live","a fake");
 const r=fixture(raw);
 const result=await checkRealResendReceivedDkim({...base,fetchFn:r.fetchFn,resolveTxt:dns});
 assert.notEqual(result.dkim,"pass");
 assert.equal(result.sender_verified_badge_allowed,false);
});
test("sender-supplied Authentication-Results PASS cannot fabricate original DKIM success",async()=>{
 const r=fixture("Authentication-Results: attacker.example; dkim=pass; spf=pass; dmarc=pass\r\n"+message);
 const result=await checkRealResendReceivedDkim({...base,fetchFn:r.fetchFn,resolveTxt:dns});
 assert.notEqual(result.dkim,"pass");
 assert.equal(result.suspicious_message_proven_fake,false);
});
test("Resend API metadata must bind exact original From and To before any raw MIME is downloaded",async()=>{
 const r=fixture(await signedMail(),{from:"Attacker <fraud@evil.example>"});
 await assert.rejects(
   checkRealResendReceivedDkim({...base,fetchFn:r.fetchFn,resolveTxt:dns}),
   /provider_message_binding_failed/
 );
 assert.equal(r.urls.length,1);
});
test("same signed raw MIME with untrusted DNS key cannot yield a verified badge",async()=>{
 const r=fixture(await signedMail());
 const result=await checkRealResendReceivedDkim({...base,fetchFn:r.fetchFn,
  resolveTxt:async()=>[["v=DKIM1; k=rsa; p=invalid-dns-key"]]
 });
 assert.equal(result.dkim_strictly_aligned,false);
 assert.equal(result.production_release_authorized,false);
});
test("missing keys fail before any network request",async()=>{
 let fetchCount=0;
 await assert.rejects(checkRealResendReceivedDkim({...base,apiKey:"",fetchFn:async()=>{fetchCount++;}}),/resend_key_missing/);
 assert.equal(fetchCount,0);
});
