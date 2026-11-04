import test from "node:test";
import assert from "node:assert/strict";
import {createHash,webcrypto} from "node:crypto";
import {execFileSync} from "node:child_process";
import {connect} from "node:net";
import {startLoopbackSmtpEvidenceTest} from "../mail-verifier/loopback-smtp-test-receiver.mjs";
import {verifyAndConsumeOfflineReceiverReceipt} from
  "../mail-verifier/verify-and-consume-receiver-test.mjs";

process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST="enabled";
process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST="enabled";
const KID="ci-ephemeral-receiver-db-key";
const FROM="Bank <alerts@bank.example>";
const TO="reply+synthetic@bharathlink.example";
const RAW=Buffer.from([
 "From: "+FROM,
 "To: user@bharathlink.example",
 "Subject: Synthetic TCP-to-PostgreSQL test",
 "MIME-Version: 1.0",
 "Content-Type: text/plain; charset=utf-8",
 "",
 "Only synthetic email for CI.",
 ""
].join("\r\n"));

function sqlQuote(value){
 // Test data only; this is NOT production SQL concatenation guidance.
 return "'"+String(value).replaceAll("'","''")+"'";
}
function psql(query){
 return execFileSync("psql",["-XAt","-v","ON_ERROR_STOP=1","-c",query],{
  encoding:"utf8",env:process.env,timeout:8000
 }).trim();
}
async function sendLoopback(server){
 const sock=connect({host:"127.0.0.1",port:server.port});
 let pending=Buffer.alloc(0);
 const answers=[],waiters=[];
 sock.on("data",chunk=>{
  pending=Buffer.concat([pending,chunk]);
  for(;;){
   const i=pending.indexOf("\r\n");
   if(i<0)break;
   const answer=pending.subarray(0,i).toString("utf8");
   pending=pending.subarray(i+2);
   if(waiters.length)waiters.shift()(answer);
   else answers.push(answer);
  }
 });
 const next=()=>new Promise((resolve,reject)=>{
  if(answers.length)return resolve(answers.shift());
  const timer=setTimeout(()=>reject(Error("SMTP synthetic read timeout")),3000);
  waiters.push(v=>{clearTimeout(timer);resolve(v);});
 });
 const write=async line=>{
  sock.write(line+"\r\n");
  return await next();
 };
 try {
  const greeting=await next();
  assert.match(greeting,/^220 /);
  assert.match(await write("EHLO sender.bank.example"),/^250 /);
  assert.match(await write("MAIL FROM:<bounce@bank.example>"),/^250 /);
  assert.match(await write("RCPT TO:<"+TO+">"),/^250 /);
  assert.match(await write("DATA"),/^354 /);
  sock.write(RAW);
  sock.write(".\r\n");
  assert.match(await next(),/^250 /);
 }finally{sock.destroy();}
 assert.equal(server.deliveries.length,1);
 return server.deliveries[0];
}
test("real loopback socket -> signed P-256 MIME receipt -> DB pinned key -> durable replay -> irreversible revoke",async t=>{
 const generated=await webcrypto.subtle.generateKey(
  {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const publicJwk=await webcrypto.subtle.exportKey("jwk",generated.publicKey);
 const pinned={
  kty:"EC",crv:"P-256",x:publicJwk.x,y:publicJwk.y
 };
 // Only public key is stored by disposable postgres. The ephemeral secret
 // remains in process memory; never serialize it or print it in CI.
 psql("insert into public.bl_mail_receiver_pins_test_v1"+
     "(kid,public_jwk,valid_from,valid_until) values("+
      sqlQuote(KID)+","+sqlQuote(JSON.stringify(pinned))+"::jsonb,"+
      "now()-interval '1 minute',now()+interval '10 minutes')");
 const receiver=await startLoopbackSmtpEvidenceTest({
  kid:KID,privateKey:generated.privateKey
 });
 t.after(async()=>receiver.close());
 const d=await sendLoopback(receiver);
 const proof=d.receiverEnvelope;
 assert.equal(proof.receipt.smtp_client_ip,"127.0.0.1");
 assert.equal(proof.receipt.raw_sha256,createHash("sha256").update(RAW).digest("hex"));
 const fromDb=async kid=>{
  const value=psql("select public_jwk::text from "+
    "public.bl_mail_receiver_pins_test_v1 where kid="+sqlQuote(kid));
  return value?JSON.parse(value):null;
 };
 const ledger=async args=>{
  return psql("select public.bl_mail_consume_receiver_test_v1("+
   sqlQuote(args.kid)+","+
   sqlQuote(args.nonce)+"::uuid,"+
   sqlQuote(args.provider_email_id)+","+
   sqlQuote(args.raw_sha256)+","+
   sqlQuote(args.receipt_sha256)+","+
   sqlQuote(args.received_at)+"::timestamptz)");
 };
 const auth={
  receiverEnvelope:proof,expectedKid:KID,
  expectedProviderEmailId:proof.receipt.provider_email_id,
  expectedFrom:FROM,expectedRecipient:TO,
  lookupPinnedReceiverPublicKey:fromDb,
  consumeSyntheticLedger:ledger
 };
 const first=await verifyAndConsumeOfflineReceiverReceipt(RAW,auth);
 assert.equal(first.status,"synthetic_recorded");
 assert.equal(first.approved_external_receiver,false);
 assert.equal(first.identity_verified,false);
 assert.equal(first.release_approved,false);
 const again=await verifyAndConsumeOfflineReceiverReceipt(RAW,auth);
 assert.equal(again.status,"synthetic_duplicate");
 const stored=psql("select count(*) from public.bl_mail_receiver_consumed_test_v1"+
   " where nonce="+sqlQuote(proof.receipt.nonce)+"::uuid");
 assert.equal(stored,"1");
 const before=psql("select count(*) from public.bl_mail_receiver_consumed_test_v1");
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(
  Buffer.concat([RAW,Buffer.from("MALICIOUS PAYMENT INSTRUCTION")]),auth
 ),/receipt_raw_mismatch/);
 assert.equal(psql("select count(*) from public.bl_mail_receiver_consumed_test_v1"),before);
 assert.equal(
  psql("select public.bl_mail_revoke_receiver_test_v1("+
   sqlQuote(KID)+",'synthetic key compromise')"),
  "revoked"
 );
 await assert.rejects(verifyAndConsumeOfflineReceiverReceipt(RAW,auth),
   /receiver_replay_or_pin_policy_denied/);
 assert.equal(psql("select count(*) from public.bl_mail_receiver_consumed_test_v1"),before);
});
