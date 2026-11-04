import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,randomUUID,webcrypto} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {AUD,canonical} from "../verify-signed-smtp-receipt.mjs";
import {deriveOfflineUnsignedMailAuthReport} from "../derive-offline-unsigned-auth-report.mjs";
import {payload,verifySignedReport} from
  "../../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const NOW=Math.floor(Date.now()/1000);
const ID="synthetic-mail-bridge-001";
const FROM="Bank Support <alerts@bank.example>";
const RECIPIENT="reply+abc123@bharathlink.example";
const KID="ephemeral-receiver-bridge-test";
const RSA=generateKeyPairSync("rsa",{modulusLength:2048});
const RSA_PEM=RSA.privateKey.export({format:"pem",type:"pkcs8"});
const RSA_DNS="v=DKIM1; k=rsa; p="+RSA.publicKey.export({
  format:"der",type:"spki"
}).toString("base64");
const RAW_BODY=()=>Buffer.from([
 "From: "+FROM,"To: person@bharathlink.example","Subject: Synthetic",
 "Date: "+new Date().toUTCString(),"MIME-Version: 1.0",
 "Content-Type: text/plain; charset=utf-8","","Offline auth integration test",""
].join("\r\n"));
async function signedMime(){
 const raw=RAW_BODY();
 const signed=await dkimSign(raw,{
  canonicalization:"relaxed/relaxed",algorithm:"rsa-sha256",strict:true,
  signTime:new Date(),
  signatureData:[{signingDomain:"bank.example",selector:"key1",privateKey:RSA_PEM}]
 });
 assert.equal(signed.errors.length,0);
 return Buffer.concat([Buffer.from(signed.signatures),raw]);
}
function dns({outage=false,missingDmarc=false}={}){
 const calls=[];
 const resolveDns=async(name,type)=>{
  calls.push(name+"|"+type);
  if(outage)throw Object.assign(Error("offline DNS outage"),{code:"ETIMEOUT"});
  if(type!=="TXT")throw Object.assign(Error("not found"),{code:"ENOTFOUND"});
  if(name==="bank.example")return [["v=spf1 ip4:192.0.2.0/24 -all"]];
  if(name==="key1._domainkey.bank.example")return [[RSA_DNS]];
  if(name==="_dmarc.bank.example")
    return missingDmarc?[]:[["v=DMARC1; p=reject; aspf=s; adkim=s"]];
  if(name==="evil.example")return [["v=spf1 ip4:192.0.2.0/24 -all"]];
  throw Object.assign(Error("not found"),{code:"ENOTFOUND"});
 };
 return {resolveDns,calls};
}
async function prepare(raw=await signedMime(),receiptChanges={}){
 const receiver=await webcrypto.subtle.generateKey({
  name:"ECDSA",namedCurve:"P-256"
 },true,["sign","verify"]);
 const pub=await webcrypto.subtle.exportKey("jwk",receiver.publicKey);
 const receipt={
  v:1,aud:AUD,kid:KID,provider_email_id:ID,
  from_address:FROM,recipient_address:RECIPIENT,
  raw_sha256:createHash("sha256").update(raw).digest("hex"),
  smtp_client_ip:"192.0.2.10",smtp_mail_from:"bounce@bank.example",
  smtp_helo:"mail.bank.example",receiver_mta:"mx.bharathlink.example",
  received_at:NOW,expires_at:NOW+120,nonce:randomUUID(),...receiptChanges
 };
 const sig=new Uint8Array(await webcrypto.subtle.sign(
  {name:"ECDSA",hash:"SHA-256"},receiver.privateKey,
  new TextEncoder().encode(canonical(receipt,NOW))));
 return {raw,params:{
  receiverEnvelope:{receipt,signature:Buffer.from(sig).toString("base64url")},
  pinnedReceiverPublicJwk:{kty:"EC",crv:"P-256",x:pub.x,y:pub.y},
  receiverKid:KID,expectedProviderEmailId:ID,expectedFrom:FROM,
  expectedRecipient:RECIPIENT,now:NOW
 }};
}
test("real offline SPF+DKIM+DMARC yields ONLY unsigned test report, with exact receipt bindings",async()=>{
 const f=await prepare();const d=dns();
 const x=await deriveOfflineUnsignedMailAuthReport(f.raw,{...f.params,resolveDns:d.resolveDns});
 assert.equal(x.report.spf,"pass");
 assert.equal(x.report.spf_domain,"bank.example");
 assert.equal(x.report.dkim,"pass");
 assert.equal(x.report.dkim_domain,"bank.example");
 assert.equal(x.report.dmarc,"pass");
 assert.equal(x.report.provider_email_id,ID);
 assert.equal(x.report.recipient_address,RECIPIENT);
 assert.equal(x.report.raw_sha256,createHash("sha256").update(f.raw).digest("hex"));
 assert.equal(x.report.nonce,f.params.receiverEnvelope.receipt.nonce);
 assert.equal(x.mode,"OFFLINE_SYNTHETIC_ONLY_UNSIGNED");
 assert.equal(x.live_sender_verified,false);
 assert.equal(x.identity_verified,false);
 assert.equal(x.safe_payment_request,false);
 assert.equal(x.production_authorized,false);
 assert.equal(x.receiver_issuer_audited,false);
 assert.equal(Object.hasOwn(x,"signature"),false);
 assert.ok(d.calls.some(s=>s==="_dmarc.bank.example|TXT"));
});
test("ephemeral test-only issuer can sign computed report that backend schema verifies",async()=>{
 const f=await prepare();const d=dns();
 const x=await deriveOfflineUnsignedMailAuthReport(f.raw,{...f.params,resolveDns:d.resolveDns});
 // Key is generated only in this test; it is not a production private key.
 const issuer=await webcrypto.subtle.generateKey({
  name:"ECDSA",namedCurve:"P-256"
 },true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",issuer.publicKey);
 const signature=new Uint8Array(await webcrypto.subtle.sign(
  {name:"ECDSA",hash:"SHA-256"},issuer.privateKey,
  new TextEncoder().encode(payload(x.report))));
 const verified=await verifySignedReport({
  report:x.report,signature:Buffer.from(signature).toString("base64url")
 },{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y},KID,NOW);
 assert.equal(verified.dmarc,"pass");
 assert.equal(verified.raw_sha256,x.report.raw_sha256);
 assert.equal(verified.recipient_address,RECIPIENT);
 assert.equal(verified.nonce,x.report.nonce);
});
test("SPF pass but unrelated MAIL FROM is not aligned and cannot yield DMARC pass",async()=>{
 const raw=RAW_BODY();
 const f=await prepare(raw,{smtp_mail_from:"bounce@evil.example"});
 const x=await deriveOfflineUnsignedMailAuthReport(raw,{
  ...f.params,resolveDns:dns().resolveDns
 });
 assert.equal(x.report.spf,"pass");
 assert.equal(x.report.spf_domain,"evil.example");
 assert.notEqual(x.report.dmarc,"pass");
 assert.notEqual(x.report.dkim,"pass");
 assert.equal(x.production_authorized,false);
});
test("SPF fail can still yield DMARC pass from exact full-body DKIM, not identity trust",async()=>{
 const f=await prepare(await signedMime(),{smtp_client_ip:"198.51.100.7"});
 const x=await deriveOfflineUnsignedMailAuthReport(f.raw,{
  ...f.params,resolveDns:dns().resolveDns
 });
 assert.equal(x.report.spf,"fail");
 assert.equal(x.report.dkim,"pass");
 assert.equal(x.report.dmarc,"pass");
 assert.equal(x.identity_verified,false);
});
test("unsigned forged Authentication-Results headers never authenticate fake mail",async()=>{
 const raw=Buffer.concat([Buffer.from(
  "Authentication-Results: fake; spf=pass; dkim=pass; dmarc=pass\r\n"+
  "Received: from fake.bank.example (192.0.2.10) by mx.bharathlink.example; Wed, 04 Nov 2026 09:00:00 GMT\r\n"
 ),RAW_BODY()]);
 const f=await prepare(raw,{smtp_client_ip:"198.51.100.7"});
 const x=await deriveOfflineUnsignedMailAuthReport(raw,{
  ...f.params,resolveDns:dns().resolveDns
 });
 assert.notEqual(x.report.dmarc,"pass");
 assert.notEqual(x.report.spf,"pass");
 assert.notEqual(x.report.dkim,"pass");
});
test("tampered raw body fails before DNS and cannot be mapped into a report",async()=>{
 const f=await prepare();const d=dns();
 const altered=Buffer.concat([f.raw,Buffer.from("\r\nPAY THIS ATTACKER")]);
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(altered,{
  ...f.params,resolveDns:d.resolveDns
 }),/receipt_raw_mismatch/);
 assert.equal(d.calls.length,0);
});
test("substituted receiver key and wrong routed recipient fail before DNS",async()=>{
 const f=await prepare(),another=await prepare(f.raw),d=dns();
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(f.raw,{
  ...f.params,pinnedReceiverPublicJwk:another.params.pinnedReceiverPublicJwk,
  resolveDns:d.resolveDns
 }),/receiver_invalid_signature/);
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(f.raw,{
  ...f.params,expectedRecipient:"attacker@bharathlink.example",
  resolveDns:d.resolveDns
 }),/wrong_recipient_binding/);
 assert.equal(d.calls.length,0);
});
test("missing DMARC DNS or DNS outage cannot yield domain auth pass",async()=>{
 const f=await prepare();
 for(const options of [{missingDmarc:true},{outage:true}]){
  const x=await deriveOfflineUnsignedMailAuthReport(f.raw,{
   ...f.params,resolveDns:dns(options).resolveDns
  });
  assert.notEqual(x.report.dmarc,"pass");
  assert.equal(x.production_authorized,false);
 }
});
test("no trusted DNS resolver, receipt or actual MIME cannot fabricate a report",async()=>{
 const f=await prepare();
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(f.raw,f.params),/independent_dns_required/);
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(f.raw,{
  ...f.params,receiverEnvelope:null,resolveDns:dns().resolveDns
 }),/receiver_envelope/);
 await assert.rejects(deriveOfflineUnsignedMailAuthReport(Buffer.from("x"),{
  ...f.params,resolveDns:dns().resolveDns
 }),/invalid_raw/);
});
