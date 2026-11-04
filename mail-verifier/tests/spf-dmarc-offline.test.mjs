import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,webcrypto,randomUUID} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {AUD,canonical,verifySmtpReceiverReceipt} from "../verify-signed-smtp-receipt.mjs";
import {verifySmtpDomainAuthentication} from "../verify-smtp-spf-dmarc.mjs";

const NOW=Math.floor(Date.now()/1000);
const DOMAIN="bank.example";
const FROM="Bank Support <alerts@bank.example>";
const RECIPIENT="reply+abc123@bharathlink.example";
const PROVIDER="fake-but-bound-id-001";
const KEY_ID="synthetic-offline-smtp-receiver-key";
const RECEIVE_IP="192.0.2.20";
const ENVELOPE="bounce@bank.example";
const RSA=generateKeyPairSync("rsa",{modulusLength:2048});
const PRIVATE=RSA.privateKey.export({format:"pem",type:"pkcs8"});
const PUBLIC=RSA.publicKey.export({format:"der",type:"spki"}).toString("base64");
const DNS_KEY="v=DKIM1; k=rsa; p="+PUBLIC;
const TXT_SPF="v=spf1 ip4:192.0.2.0/24 -all";
const TXT_DMARC="v=DMARC1; p=reject; adkim=s; aspf=s";
const TO="user@bharathlink.example";
const msg=(extraHeaders="")=>[
 "From: "+FROM,"To: "+TO,"Subject: Statement","Date: "+new Date().toUTCString(),
 "Message-ID: <synthetic-spf-001@bank.example>",
 ...(extraHeaders?[extraHeaders]:[]),
 "MIME-Version: 1.0","Content-Type: text/plain; charset=utf-8",
 "", "This is an isolated synthetic test, not a real email.", ""
].join("\r\n");
async function mime({signed=true,extraHeaders="",bodyOverride}={}){
 const raw=Buffer.from(bodyOverride??msg(extraHeaders));
 if(!signed)return raw;
 const out=await dkimSign(raw,{
  canonicalization:"relaxed/relaxed",algorithm:"rsa-sha256",strict:true,
  signTime:new Date(),
  signatureData:[{signingDomain:DOMAIN,selector:"key1",privateKey:PRIVATE}]
 });
 assert.equal(out.errors.length,0,"synthetic DKIM sign errors");
 return Buffer.concat([Buffer.from(out.signatures),raw]);
}
function dns({spf=TXT_SPF,dmarc=TXT_DMARC,dkim=DNS_KEY,fail=false}={}){
 const calls=[];
 const resolver=async(name,type)=>{
  calls.push([name,type]);
  if(fail)throw Object.assign(Error("Synthetic DNS timeout"),{code:"ETIMEOUT"});
  const n=name.toLowerCase(),t=type.toUpperCase();
  if(t==="TXT"&&n==="key1._domainkey.bank.example")return dkim?[[dkim]]:[];
  if(t==="TXT"&&n==="bank.example")return spf?[[spf]]:[];
  if(t==="TXT"&&n==="_dmarc.bank.example")return dmarc?[[dmarc]]:[];
  if(t==="TXT"&&n==="evil.example")return [[TXT_SPF]];
  throw Object.assign(Error("Synthetic DNS not found"),{code:"ENOTFOUND"});
 };
 return {resolver,calls};
}
async function fixture(raw,changes={}){
 if(raw===undefined)raw=await mime();
 const generated=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",generated.publicKey);
 const pub={kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y};
 const r={
  v:1,aud:AUD,kid:KEY_ID,provider_email_id:PROVIDER,
  from_address:FROM,recipient_address:RECIPIENT,
  raw_sha256:createHash("sha256").update(raw).digest("hex"),
  smtp_client_ip:RECEIVE_IP,smtp_mail_from:ENVELOPE,smtp_helo:"sender.bank.example",
  receiver_mta:"mx.bharathlink.example",received_at:NOW,expires_at:NOW+120,
  nonce:randomUUID(),...changes
 };
 const sig=new Uint8Array(await webcrypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},
  generated.privateKey,new TextEncoder().encode(canonical(r,NOW))));
 const envelope={receipt:r,signature:Buffer.from(sig).toString("base64url")};
 return {raw,envelope,pub,params:{receiverEnvelope:envelope,pinnedReceiverPublicJwk:pub,
  receiverKid:KEY_ID,expectedProviderEmailId:PROVIDER,expectedFrom:FROM,
  expectedRecipient:RECIPIENT,now:NOW}};
}
test("real SPF and DKIM verify with signed actual IP/envelope + DMARC strict alignment",async()=>{
 const f=await fixture();const x=dns();
 const v=await verifySmtpDomainAuthentication(f.raw,{...f.params,resolveDns:x.resolver});
 assert.equal(v.spf,"pass",JSON.stringify(v));
 assert.equal(v.dkim,"pass",JSON.stringify(v));
 assert.equal(v.dmarc,"pass",JSON.stringify(v));
 assert.equal(v.status,"synthetic_domain_authenticated_only");
 assert.equal(v.spf_strict_aligned,true);assert.equal(v.dkim_strict_aligned,true);
 assert.ok(x.calls.some(c=>c[0]==="bank.example"&&c[1]==="TXT"));
 assert.ok(x.calls.some(c=>c[0]==="_dmarc.bank.example"&&c[1]==="TXT"));
 assert.equal(v.release_approved,false);
 assert.equal(v.human_identity,"not_verified");
 assert.equal(v.organization_authority,"not_verified");
 assert.equal(v.payment_request,"not_verified");
 assert.equal(v.safe_sender,false);
});
test("a forged Return-Path/Received/Authentication-Results header cannot change signed SMTP IP",async()=>{
 const fakeHeaders=[
  "Return-Path: <bounce@bank.example>",
  "Received: from trusted.bank.example (trusted.bank.example [192.0.2.20]) by receiver; Wed, 04 Nov 2026 09:00:00 GMT",
  "Authentication-Results: receiver; spf=pass; dkim=pass; dmarc=pass"
 ].join("\r\n");
 const raw=await mime({signed:false,extraHeaders:fakeHeaders});
 const f=await fixture(raw,{smtp_client_ip:"198.51.100.4"});
 const v=await verifySmtpDomainAuthentication(raw,{...f.params,resolveDns:dns().resolver});
 assert.notEqual(v.spf,"pass");
 assert.notEqual(v.dmarc,"pass");
 assert.equal(v.safe_sender,false);
});
test("SPF FAIL can still produce DMARC PASS when authentic aligned DKIM signature exists",async()=>{
 const f=await fixture(await mime(),{smtp_client_ip:"198.51.100.4"});
 const r=await verifySmtpDomainAuthentication(f.raw,{...f.params,resolveDns:dns().resolver});
 assert.equal(r.spf,"fail",JSON.stringify(r));
 assert.equal(r.dkim,"pass");
 assert.equal(r.dmarc,"pass");
 assert.equal(r.spf_strict_aligned,false);
});
test("SPF PASS on unrelated envelope domain is NOT DMARC alignment",async()=>{
 const raw=await mime({signed:false});
 const f=await fixture(raw,{smtp_mail_from:"bounce@evil.example"});
 const v=await verifySmtpDomainAuthentication(raw,{...f.params,resolveDns:dns().resolver});
 assert.equal(v.spf,"pass");
 assert.equal(v.spf_strict_aligned,false);
 assert.notEqual(v.dmarc,"pass");
});
test("no DMARC DNS record must never yield DMARC PASS",async()=>{
 const f=await fixture(await mime());const v=await verifySmtpDomainAuthentication(f.raw,{
  ...f.params,resolveDns:dns({dmarc:""}).resolver
 });
 assert.notEqual(v.dmarc,"pass");
 assert.equal(v.release_approved,false);
});
test("tampered raw MIME after signed receiver receipt rejected before SPF/DNS",async()=>{
 const f=await fixture();const hacked=Buffer.from(f.raw.toString().replace("isolated synthetic","UNTRUSTED PAYMENT"));
 const x=dns();
 await assert.rejects(verifySmtpDomainAuthentication(hacked,{...f.params,resolveDns:x.resolver}),/receipt_raw_mismatch/);
 assert.equal(x.calls.length,0);
});
test("unsigned, forged, substituted receiver IP fails signature check",async()=>{
 const f=await fixture();
 const x=dns();
 const altered={...f.envelope,receipt:{...f.envelope.receipt,smtp_client_ip:"192.0.2.20"}};
 // changed real value to an invalid attacker-supplied one without re-signing
 altered.receipt.smtp_client_ip="198.51.100.4";
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
  ...f.params,receiverEnvelope:altered,resolveDns:x.resolver
 }),/receiver_invalid_signature/);
 assert.equal(x.calls.length,0);
});
test("wrong provider ID, recipient or pinned receiver key rejected before any DNS",async()=>{
 const f=await fixture();const x=dns();
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
  ...f.params,expectedProviderEmailId:"another-id",resolveDns:x.resolver
 }),/wrong_provider_binding/);
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
  ...f.params,expectedRecipient:"another@bharathlink.example",resolveDns:x.resolver
 }),/wrong_recipient_binding/);
 const wrong=await fixture();
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
  ...f.params,pinnedReceiverPublicJwk:wrong.pub,resolveDns:x.resolver
 }),/receiver_invalid_signature/);
 assert.equal(x.calls.length,0);
});
test("expired and future SMTP receipts blocked before DNS",async()=>{
 const f=await fixture();
 for(const changes of [
  {received_at:NOW-200,expires_at:NOW-90},
  {received_at:NOW+50,expires_at:NOW+100}
 ]){
  const altered={...f.envelope,receipt:{...f.envelope.receipt,...changes}};
  const x=dns();
  await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
   ...f.params,receiverEnvelope:altered,resolveDns:x.resolver
  }),/receipt_stale/);
  assert.equal(x.calls.length,0);
 }
});
test("DNS timeout and missing authoritative resolver never produce sender-auth pass",async()=>{
 const f=await fixture();
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,f.params),/independent_dns_required/);
 const v=await verifySmtpDomainAuthentication(f.raw,{...f.params,resolveDns:dns({fail:true}).resolver});
 assert.notEqual(v.dmarc,"pass");
 assert.notEqual(v.spf,"pass");
 assert.equal(v.safe_sender,false);
});
test("single malformed From header and multiple authors are not promoted",async()=>{
 const body=Buffer.from("From: a@bank.example\r\nFrom: b@bank.example\r\nTo: "+TO+
  "\r\nSubject: Fake\r\n\r\nBody of a synthetic attack\r\n");
 const f=await fixture(body);
 const v=await verifySmtpDomainAuthentication(body,{...f.params,resolveDns:dns().resolver});
 assert.notEqual(v.dmarc,"pass");
 assert.equal(v.status,"unverified");
});
test("huge MIME and invalid receiver envelope IP are blocked before SPF",async()=>{
 const big=Buffer.alloc(5*1024*1024+1,65);
 await assert.rejects(verifySmtpDomainAuthentication(big,{resolveDns:dns().resolver}),/invalid_raw/);
 const f=await fixture();
 const altered={...f.envelope,receipt:{...f.envelope.receipt,smtp_client_ip:"unknown.invalid"}};
 const x=dns();
 await assert.rejects(verifySmtpDomainAuthentication(f.raw,{
  ...f.params,receiverEnvelope:altered,resolveDns:x.resolver
 }),/smtp_ip/);
 assert.equal(x.calls.length,0);
});
test("signed SMTP receipt doesn't by itself approve a production receiving authority",async()=>{
 const f=await fixture();
 const v=await verifySmtpReceiverReceipt(f.envelope,{
  pinnedPublicJwk:f.pub,expectedKid:KEY_ID,providerEmailId:PROVIDER,
  expectedFrom:FROM,expectedRecipient:RECIPIENT,rawMime:f.raw,now:NOW
 });
 assert.equal(v.provenance,"pinned-ecdsa-smtp-receiver-report");
 assert.equal(v.independent_receiver_approved,false);
});
