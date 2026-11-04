import test from "node:test";
import assert from "node:assert/strict";
import {connect} from "node:net";
import {generateKeyPairSync,webcrypto,createHash} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {startLoopbackSmtpEvidenceTest} from "../loopback-smtp-test-receiver.mjs";
import {verifySmtpReceiverReceipt} from "../verify-signed-smtp-receipt.mjs";
import {verifySmtpDomainAuthentication} from "../verify-smtp-spf-dmarc.mjs";
import {deriveOfflineUnsignedMailAuthReport} from "../derive-offline-unsigned-auth-report.mjs";

process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST="enabled";
const FROM="Bank <alerts@bank.example>";
const TO="reply+demo@bharathlink.example";
const KID="ephemeral-loopback-receiver-key";
const REPORT_KID="separate-ephemeral-report-issuer";
const RSA=generateKeyPairSync("rsa",{modulusLength:2048});
const RSA_PRIVATE=RSA.privateKey.export({format:"pem",type:"pkcs8"});
const RSA_DNS="v=DKIM1; k=rsa; p="+
 RSA.publicKey.export({format:"der",type:"spki"}).toString("base64");
function plain(extra=[],body="Synthetic mail body"){
 return Buffer.from([
  "From: "+FROM,"To: user@bharathlink.example","Subject: Test",
  "Date: "+new Date().toUTCString(),...extra,
  "MIME-Version: 1.0","Content-Type: text/plain; charset=utf-8",
  "",body,""
 ].join("\r\n"));
}
async function signed(){
 const raw=plain();
 const sig=await dkimSign(raw,{
  canonicalization:"relaxed/relaxed",algorithm:"rsa-sha256",strict:true,
  signTime:new Date(),
  signatureData:[{signingDomain:"bank.example",selector:"s1",privateKey:RSA_PRIVATE}]
 });
 assert.equal(sig.errors.length,0);
 return Buffer.concat([Buffer.from(sig.signatures),raw]);
}
async function setup(t){
 const k=await webcrypto.subtle.generateKey(
  {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",k.publicKey);
 const server=await startLoopbackSmtpEvidenceTest({
  kid:KID,privateKey:k.privateKey
 });
 t.after(async()=>server.close());
 return {server,publicJwk:{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y}};
}
async function smtpClient(server){
 const socket=connect({host:server.host,port:server.port});
 const lines=[],pending=[],maxWait=3500;
 let buffer=Buffer.alloc(0);
 socket.on("data",chunk=>{
  buffer=Buffer.concat([buffer,chunk]);
  for(;;){
   const i=buffer.indexOf("\r\n");
   if(i<0)break;
   const line=buffer.subarray(0,i).toString("ascii");
   buffer=buffer.subarray(i+2);
   if(pending.length)pending.shift()(line);
   else lines.push(line);
  }
 });
 socket.on("error",()=>{});
 await new Promise((res,rej)=>{
  if(socket.readyState==="open")return res();
  socket.once("connect",res);
  socket.once("error",rej);
 });
 const next=()=>new Promise((resolve,reject)=>{
  if(lines.length)return resolve(lines.shift());
  const timer=setTimeout(()=>reject(Error("SMTP response timeout")),maxWait);
  pending.push(line=>{clearTimeout(timer);resolve(line);});
 });
 const send=async cmd=>{
  socket.write(cmd+"\r\n");
  return await next();
 };
 const finish=async raw=>{
  const text=raw.toString("latin1");
  assert.ok(text.endsWith("\r\n"),"test original raw MIME ends in CRLF");
  // SMTP dot stuffing: transmission over TCP is not equal to decoded MIME.
  const stuffed=text.replace(/(^|\r\n)\./g,"$1..");
  socket.write(Buffer.from(stuffed+".\r\n","latin1"));
  return await next();
 };
 return {socket,next,send,finish,close:()=>socket.destroy()};
}
async function transmit(t,raw,params={}){
 const x=await setup(t);
 const client=await smtpClient(x.server);
 t.after(()=>client.close());
 assert.match(await client.next(),/^220 /);
 assert.match(await client.send("EHLO mail.bank.example"),/^250 /);
 assert.match(await client.send("MAIL FROM:<"+(params.mailFrom||"bounce@bank.example")+">"),/^250 /);
 assert.match(await client.send("RCPT TO:<"+TO+">"),/^250 /);
 assert.match(await client.send("DATA"),/^354 /);
 assert.match(await client.finish(raw),/^250 /);
 assert.equal(x.server.deliveries.length,1);
 const d=x.server.deliveries[0];
 return {...x,...d};
}
function fakeDns(){
 const calls=[];
 const resolveDns=async(name,type)=>{
  calls.push([name,type]);
  if(type==="TXT"&&name==="bank.example")
    return [["v=spf1 ip4:127.0.0.1 -all"]];
  if(type==="TXT"&&name==="s1._domainkey.bank.example")return [[RSA_DNS]];
  if(type==="TXT"&&name==="_dmarc.bank.example")
    return [["v=DMARC1; p=reject; aspf=s; adkim=s"]];
  throw Object.assign(Error("not found"),{code:"ENOTFOUND"});
 };
 return {resolveDns,calls};
}
function options(x){
 return {
  receiverEnvelope:x.receiverEnvelope,pinnedReceiverPublicJwk:x.publicJwk,
  receiverKid:KID,offlineReportIssuerKid:REPORT_KID,
  expectedProviderEmailId:x.receiverEnvelope.receipt.provider_email_id,
  expectedFrom:FROM,expectedRecipient:TO
 };
}
test("real 127.0.0.1 socket HELO MAIL FROM RCPT and DKIM MIME become signed independent receipt",async t=>{
 const raw=await signed(),x=await transmit(t,raw);
 const r=x.receiverEnvelope.receipt;
 assert.equal(x.origin,"REAL_LOOPBACK_TCP_SYNTHETIC_RECEIVER_ONLY");
 assert.equal(x.production_authorized,false);
 assert.equal(x.external_receiver_audited,false);
 assert.equal(r.smtp_client_ip,"127.0.0.1");
 assert.equal(r.smtp_mail_from,"bounce@bank.example");
 assert.equal(r.smtp_helo,"mail.bank.example");
 assert.equal(r.recipient_address,TO);
 assert.equal(r.from_address,FROM);
 assert.equal(r.raw_sha256,createHash("sha256").update(raw).digest("hex"));
 assert.deepEqual(x.rawMime,raw);
 const verified=await verifySmtpReceiverReceipt(x.receiverEnvelope,{
  pinnedPublicJwk:x.publicJwk,expectedKid:KID,
  providerEmailId:r.provider_email_id,
  expectedFrom:FROM,expectedRecipient:TO,rawMime:raw
 });
 assert.equal(verified.smtp_client_ip,"127.0.0.1");
 assert.equal(verified.independent_receiver_approved,false);
});
test("socket-evidenced email reaches SPF DKIM DMARC and only UNSIGNED report schema",async t=>{
 const x=await transmit(t,await signed()),d=fakeDns();
 const v=await verifySmtpDomainAuthentication(x.rawMime,{
  ...options(x),resolveDns:d.resolveDns
 });
 assert.equal(v.spf,"pass",JSON.stringify(v));
 assert.equal(v.dkim,"pass",JSON.stringify(v));
 assert.equal(v.dmarc,"pass",JSON.stringify(v));
 assert.equal(v.status,"synthetic_domain_authenticated_only");
 assert.equal(v.release_approved,false);
 const result=await deriveOfflineUnsignedMailAuthReport(x.rawMime,{
  ...options(x),resolveDns:fakeDns().resolveDns
 });
 assert.equal(result.report.dkim,"pass");
 assert.equal(result.report.dmarc,"pass");
 assert.equal(result.report.kid,REPORT_KID);
 assert.equal(result.report.raw_sha256,x.receiverEnvelope.receipt.raw_sha256);
 assert.equal(result.report.nonce,x.receiverEnvelope.receipt.nonce);
 assert.equal(result.live_sender_verified,false);
 assert.equal(result.production_authorized,false);
 assert.equal(Object.hasOwn(result,"signature"),false);
});
test("fake Received, Return-Path and Authentication-Results cannot change TCP client IP or SMTP envelope",async t=>{
 const raw=plain([
  "Received: from trust.bank.example (192.0.2.42) by mx.bharathlink.example",
  "Return-Path: <not-real@bank.example>",
  "Authentication-Results: mx.bharathlink.example; spf=pass; dkim=pass; dmarc=pass"
 ]);
 const x=await transmit(t,raw,{mailFrom:"fake@bank.example"});
 assert.equal(x.receiverEnvelope.receipt.smtp_client_ip,"127.0.0.1");
 assert.equal(x.receiverEnvelope.receipt.smtp_mail_from,"fake@bank.example");
 const evaled=await verifySmtpDomainAuthentication(raw,{
  ...options(x),resolveDns:fakeDns().resolveDns
 });
 assert.notEqual(evaled.dkim,"pass");
 assert.equal(evaled.safe_sender,false);
 assert.equal(evaled.release_approved,false);
});
test("original signed raw MIME cannot be modified after receipt even when attacker retains signature",async t=>{
 const x=await transmit(t,await signed());
 const tampered=Buffer.concat([x.rawMime,Buffer.from("\r\nPay to unknown account\r\n")]);
 await assert.rejects(verifySmtpReceiverReceipt(x.receiverEnvelope,{
  pinnedPublicJwk:x.publicJwk,expectedKid:KID,
  providerEmailId:x.receiverEnvelope.receipt.provider_email_id,
  expectedFrom:FROM,expectedRecipient:TO,rawMime:tampered
 }),/receipt_raw_mismatch/);
});
test("different pinned receiver key cannot certify a valid local receipt",async t=>{
 const x=await transmit(t,await signed());
 const other=await webcrypto.subtle.generateKey(
  {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",other.publicKey);
 await assert.rejects(verifySmtpReceiverReceipt(x.receiverEnvelope,{
  pinnedPublicJwk:{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y},
  expectedKid:KID,providerEmailId:x.receiverEnvelope.receipt.provider_email_id,
  expectedFrom:FROM,expectedRecipient:TO,rawMime:x.rawMime
 }),/receiver_invalid_signature/);
});
test("dot-stuffed SMTP DATA is reconstructed as exact raw MIME before hashing",async t=>{
 const raw=plain([],"First line\r\n.starts-with-dot\r\n..two-dots");
 const x=await transmit(t,raw);
 assert.deepEqual(x.rawMime,raw);
 assert.equal(x.receiverEnvelope.receipt.raw_sha256,createHash("sha256").update(raw).digest("hex"));
});
test("two From headers never produce a signed receipt",async t=>{
 const x=await setup(t),client=await smtpClient(x.server);
 t.after(()=>client.close());
 await client.next();
 await client.send("EHLO mail.bank.example");
 await client.send("MAIL FROM:<bounce@bank.example>");
 await client.send("RCPT TO:<"+TO+">");
 await client.send("DATA");
 const raw=Buffer.from("From: "+FROM+"\r\nFrom: Fake <fake@evil.example>\r\nTo: x@bharathlink.example\r\n\r\nBody\r\n");
 assert.match(await client.finish(raw),/^550 /);
 assert.equal(x.server.deliveries.length,0);
});
test("STARTTLS and XCLIENT forwarding spoofing commands are not available",async t=>{
 for(const command of ["STARTTLS","XCLIENT ADDR=192.0.2.42","AUTH PLAIN abc"]){
  const x=await setup(t),c=await smtpClient(x.server);
  t.after(()=>c.close());
  await c.next();
  assert.match(await c.send(command),/^502 /);
  assert.equal(x.server.deliveries.length,0);
 }
});
test("no relaying outside synthetic recipient domain and no out-of-order SMTP commands",async t=>{
 const x=await setup(t),c=await smtpClient(x.server);
 t.after(()=>c.close());
 await c.next();
 assert.match(await c.send("RCPT TO:<x@bharathlink.example>"),/^503 /);
 assert.equal(x.server.deliveries.length,0);
 const y=await setup(t),c2=await smtpClient(y.server);
 t.after(()=>c2.close());
 await c2.next();
 await c2.send("EHLO mail.bank.example");
 await c2.send("MAIL FROM:<bounce@bank.example>");
 assert.match(await c2.send("RCPT TO:<victim@gmail.com>"),/^550 /);
 assert.equal(y.server.deliveries.length,0);
});
test("oversized data line rejected before signed receipt",async t=>{
 const x=await setup(t),c=await smtpClient(x.server);
 t.after(()=>c.close());
 await c.next();
 await c.send("EHLO mail.bank.example");
 await c.send("MAIL FROM:<bounce@bank.example>");
 await c.send("RCPT TO:<"+TO+">");
 await c.send("DATA");
 assert.match(await c.send("A".repeat(1100)),/^552 /);
 assert.equal(x.server.deliveries.length,0);
});
test("receiver refuses to open without explicit loopback opt-in",async()=>{
 const prev=process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST;
 delete process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST;
 try{
  await assert.rejects(startLoopbackSmtpEvidenceTest(),/loopback_test_guard_required/);
 }finally{process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST=prev;}
});
