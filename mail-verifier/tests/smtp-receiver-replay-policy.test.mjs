import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto,createHash,randomUUID} from "node:crypto";
import {AUD,canonical} from "../verify-signed-smtp-receipt.mjs";
import {verifyAndConsumeOfflineReceiverReceipt} from "../verify-and-consume-receiver-test.mjs";

process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST="enabled";
const RAW=Buffer.from(
 "From: Bank <alerts@bank.example>\r\nTo: x@bharathlink.example\r\n"+
 "Subject: Synthetic replay test\r\n\r\nSynthetic only\r\n"
);
const KID="synthetic-p256-key-2026";
const FROM="Bank <alerts@bank.example>";
const RECIPIENT="reply+synthetic@bharathlink.example";
const PROVIDER="synthetic-provider-001";
const NOW=Math.floor(Date.now()/1000);

async function fixture(changes={},privateKeyOverride){
 const pair=await webcrypto.subtle.generateKey(
   {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",pair.publicKey);
 const publicJwk={kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y};
 const receipt={
  v:1,aud:AUD,kid:KID,provider_email_id:PROVIDER,
  from_address:FROM,recipient_address:RECIPIENT,
  raw_sha256:createHash("sha256").update(RAW).digest("hex"),
  smtp_client_ip:"127.0.0.1",smtp_mail_from:"bounce@bank.example",
  smtp_helo:"mail.bank.example",receiver_mta:"mx.bharathlink.example",
  received_at:NOW,expires_at:NOW+110,
  nonce:randomUUID(),...changes
 };
 const sig=Buffer.from(new Uint8Array(await webcrypto.subtle.sign(
   {name:"ECDSA",hash:"SHA-256"},
   privateKeyOverride??pair.privateKey,
   new TextEncoder().encode(canonical(receipt,NOW))
 ))).toString("base64url");
 return {
  publicJwk,
  receiverEnvelope:{receipt,signature:sig}
 };
}
function options(f,ledger,lookup=async kid=>kid===KID?f.publicJwk:null){
 return {
  receiverEnvelope:f.receiverEnvelope,
  expectedKid:KID,
  expectedProviderEmailId:PROVIDER,expectedFrom:FROM,
  expectedRecipient:RECIPIENT,
  lookupPinnedReceiverPublicKey:lookup,
  consumeSyntheticLedger:ledger,now:NOW
 };
}
function syntheticLedger(){
 const seenNonce=new Map(),seenProvider=new Map();
 const received=[];
 return {
  received,
  consume:async entry=>{
   received.push(entry);
   const previous=seenNonce.get(entry.nonce)||seenProvider.get(entry.provider_email_id);
   if(previous)return JSON.stringify(previous)===JSON.stringify(entry)
     ?"duplicate":"replay_or_conflict";
   seenNonce.set(entry.nonce,entry);
   seenProvider.set(entry.provider_email_id,entry);
   return "recorded";
  }
 };
}
test("pinned P-256 receipt and original MIME bind all six SQL parameters before store",async()=>{
 const f=await fixture(),l=syntheticLedger();
 const x=await verifyAndConsumeOfflineReceiverReceipt(RAW,options(f,l.consume));
 assert.equal(x.status,"synthetic_recorded");
 assert.equal(l.received.length,1);
 assert.equal(l.received[0].kid,KID);
 assert.equal(l.received[0].nonce,f.receiverEnvelope.receipt.nonce);
 assert.equal(l.received[0].provider_email_id,PROVIDER);
 assert.equal(l.received[0].raw_sha256,createHash("sha256").update(RAW).digest("hex"));
 assert.match(l.received[0].receipt_sha256,/^[a-f0-9]{64}$/);
 assert.equal(l.received[0].received_at,new Date(NOW*1000).toISOString());
 assert.equal(x.live_sender_verified,false);
 assert.equal(x.identity_verified,false);
 assert.equal(x.payment_request_safe,false);
 assert.equal(x.approved_external_receiver,false);
 assert.equal(x.release_approved,false);
});
test("bit-for-bit repeat of authenticated receipt is only an idempotent synthetic duplicate",async()=>{
 const f=await fixture(),l=syntheticLedger(),args=options(f,l.consume);
 assert.equal((await verifyAndConsumeOfflineReceiverReceipt(RAW,args)).status,"synthetic_recorded");
 assert.equal((await verifyAndConsumeOfflineReceiverReceipt(RAW,args)).status,"synthetic_duplicate");
});
test("valid signed receipt replaying same provider with different nonce is rejected by ledger",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await verifyAndConsumeOfflineReceiverReceipt(RAW,options(f,l.consume));
 const f2=await fixture();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,options(f2,l.consume)),
   /receiver_replay_or_pin_policy_denied/);
});
test("raw MIME tampering is stopped before reaching replay ledger",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
   Buffer.concat([RAW,Buffer.from("\r\nPAY FRAUD")]),options(f,l.consume)
 ),/receipt_raw_mismatch/);
 assert.equal(l.received.length,0);
});
test("untrusted caller cannot replace the configured pinned receiver public key",async()=>{
 const real=await fixture(),attacker=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,{
  ...options(real,l.consume),lookupPinnedReceiverPublicKey:async()=>attacker.publicJwk
 }),/receiver_invalid_signature/);
 assert.equal(l.received.length,0);
});
test("unknown receiver key and changed receipt kid are denied before storage",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,options(
  f,l.consume,async()=>null)),/receiver_key_not_pinned/);
 const altered={...f,receiverEnvelope:{
  ...f.receiverEnvelope,receipt:{...f.receiverEnvelope.receipt,kid:"attacker-key"}
 }};
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
  RAW,options(altered,l.consume)
 ),/unexpected_receiver_key/);
 assert.equal(l.received.length,0);
});
test("wrong expected recipient or provider email id fails before consumption",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,{
  ...options(f,l.consume),expectedRecipient:"another@bharathlink.example"
 }),/wrong_recipient_binding/);
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,{
  ...options(f,l.consume),expectedProviderEmailId:"different-provider"
 }),/wrong_provider_binding/);
 assert.equal(l.received.length,0);
});
test("stale signed receipt is not used even with a correct pinned key",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
  RAW,{...options(f,l.consume),now:NOW+131}
 ),/receipt_stale/);
 assert.equal(l.received.length,0);
});
test("unknown or disabled SQL/ledger authorization is strictly a denial",async()=>{
 const f=await fixture();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,{
  ...options(f,async()=> "revoked_key")
 }),/receiver_replay_or_pin_policy_denied/);
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,{
  ...options(f,async()=> "inactive_key")
 }),/receiver_replay_or_pin_policy_denied/);
});
test("no offline test guard or independent key registry cannot authorize",async()=>{
 const f=await fixture(),l=syntheticLedger();
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
  RAW,{...options(f,l.consume),lookupPinnedReceiverPublicKey:undefined}
 ),/independent_registry_and_ledger_required/);
 const old=process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST;
 delete process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST;
 try{
  await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
   RAW,options(f,l.consume)
  ),/offline_replay_test_guard_required/);
 }finally{process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST=old;}
 assert.equal(l.received.length,0);
});
