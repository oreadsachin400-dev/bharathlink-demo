import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {createRequire} from "node:module";
const require=createRequire(import.meta.url);
const trustEngine=require("../../bharatmail-trust-engine.js");
import {inspectCloudflareEmailRoutingFixture,authResults,MAX_RAW_BYTES} from
  "../cloudflare-email-routing-readonly.mjs";
const SCOPE="isolated-cloudflare-email-routing-fixture-only";
const DOMAIN="mail.test.bharathlink.example";
const FROM="Bank Support <alerts@bank.example>";
const RAW=Buffer.from([
  "From: "+FROM,
  "To: test-user@"+DOMAIN,
  "Subject: No live test",
  "Authentication-Results: mx.attacker.example; spf=pass; dkim=pass; dmarc=pass",
  "Reply-To: scammer@different.example",
  "",
  "synthetic offline fixture only",
  ""
].join("\r\n"));
const TRUSTED_SYNTAX="mx.cloudflare.net; spf=pass smtp.mailfrom=bank.example; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example";
function mock({
  headers={},from="bounce@bank.example",to="test-user@"+DOMAIN,
  raw=RAW,rawSize=raw.length
}={}){
  const all=new Headers({
    "from":FROM,
    "authentication-results":TRUSTED_SYNTAX,
    "reply-to":"scammer@different.example",
    ...headers
  });
  const stream=new ReadableStream({
    start(controller){controller.enqueue(new Uint8Array(raw));controller.close();}
  });
  return {from,to,headers:all,raw:stream,rawSize};
}
const evaluate=(input,options={})=>inspectCloudflareEmailRoutingFixture(
  input,{scope:SCOPE,allowedTestRecipientDomain:DOMAIN,...options}
);
test("Cloudflare-format mock keeps SPF DKIM DMARC only as upstream fixture observations",async()=>{
  const v=await evaluate(mock());
  assert.equal(v.status,"OFFLINE_WORKER_EVENT_FIXTURE_ONLY");
  assert.equal(v.upstream_spf_observed,"pass");
  assert.equal(v.upstream_dkim_observed,"pass");
  assert.equal(v.upstream_dmarc_observed,"pass");
  assert.equal(v.raw_sha256,createHash("sha256").update(RAW).digest("hex"));
  assert.equal(v.envelope_from,"bounce@bank.example");
  assert.equal(v.author_from,"alerts@bank.example");
  assert.equal(v.author_domain,"bank.example");
  for(const name of ["cryptographic_origin_proven","strict_dmarc_alignment_reverified",
  "live_sender_domain_verified","sender_identity_verified",
  "organization_authority_verified","payment_beneficiary_verified",
  "production_authorized","upstream_auth_results_audited"]){
    assert.equal(v[name],false,name);
  }
  assert.ok(Object.isFrozen(v));
});
test("real header Reply-To destination different from RFC5322 From becomes a caution",async()=>{
 const v=await evaluate(mock());
 assert.equal(v.reply_to_address,"scammer@different.example");
 assert.equal(v.reply_to_domain_mismatch_caution,true);
 assert.equal(v.sender_identity_verified,false);
});
test("same domain Reply-To is not mislabeled as suspicious",async()=>{
 const v=await evaluate(mock({headers:{"reply-to":"support@bank.example"}}));
 assert.equal(v.reply_to_domain_mismatch_caution,false);
 assert.equal(v.reply_to_unparseable_caution,false);
});
test("duplicate comma-separated Reply-To fails closed with unparseable caution",async()=>{
 const v=await evaluate(mock({headers:{"reply-to":"safe@bank.example, fake@evil.example"}}));
 assert.equal(v.reply_to_address,"");
 assert.equal(v.reply_to_domain_mismatch_caution,false);
 assert.equal(v.reply_to_unparseable_caution,true);
});
test("malformed visible From never replaced by SMTP envelope",async()=>{
 const v=await evaluate(mock({headers:{"from":"CEO <notvalid>"}}));
 assert.equal(v.author_from,"");
 assert.equal(v.author_domain,"");
 assert.equal(v.sender_identity_verified,false);
});
test("forged Authentication-Results embedded in raw MIME never supply provider verdicts",async()=>{
 const v=await evaluate(mock({headers:{"authentication-results":""}}));
 assert.equal(v.upstream_spf_observed,"not_checked");
 assert.equal(v.upstream_dkim_observed,"not_checked");
 assert.equal(v.upstream_dmarc_observed,"not_checked");
});
test("authserv-id prefix spoofing and malformed method lists fail closed",()=>{
 for(const h of [
  "mx.cloudflare.net.evil.example; spf=pass; dkim=pass; dmarc=pass",
  "mx.cloudflare.net; spf=pass; dkim=pass",
  "mx.cloudflare.net; spf=pass; dkim=pass; dkim=fail; dmarc=pass",
  "mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass, mx.bad; dmarc=fail",
  "mx.cloudflare.net\r\nAuthentication-Results: mx.bad; dmarc=pass",
  "bad.example; spf=pass; dkim=pass; dmarc=pass",
 ]){
  assert.equal(authResults(h).trustedSyntax,false,h);
  assert.equal(authResults(h).dmarc,"not_checked",h);
 }
});
test("nonpass Cloudflare-shaped method verdicts never silently upgraded to pass",async()=>{
 const v=await evaluate(mock({headers:{
  "authentication-results":"mx.cloudflare.net; spf=fail; dkim=none; dmarc=fail"
 }}));
 assert.equal(v.upstream_spf_observed,"fail");
 assert.equal(v.upstream_dkim_observed,"none");
 assert.equal(v.upstream_dmarc_observed,"fail");
 assert.equal(v.live_sender_domain_verified,false);
});
test("only explicit isolated worker fixture guard and dedicated test subdomain accepted",async()=>{
 await assert.rejects(inspectCloudflareEmailRoutingFixture(mock(),{
  scope:"production",allowedTestRecipientDomain:DOMAIN
 }),/offline_worker_test_guard_required/);
 await assert.rejects(evaluate(mock(),{
  allowedTestRecipientDomain:"bharathlink.com"
 }),/separate_test_subdomain_required/);
 await assert.rejects(evaluate(mock({
  to:"user@bharathlink.com"
 })),/test_recipient_domain_mismatch/);
});
test("receiver routing uses envelope RCPT TO not spoofable MIME To header",async()=>{
 const v=await evaluate(mock());
 assert.equal(v.recipient,"test-user@"+DOMAIN);
 assert.equal(v.production_authorized,false);
});
test("invalid envelope MAIL FROM cannot be mistaken for verified RFC5322 From",async()=>{
 await assert.rejects(evaluate(mock({from:"evil@bank.example,other@bank.example"})),
  /ambiguous_mail_address/);
});
test("missing or exceeded raw MIME size always rejects",async()=>{
 await assert.rejects(evaluate(mock({rawSize:MAX_RAW_BYTES+1})),
  /raw_size_unavailable_or_too_large/);
 await assert.rejects(evaluate(mock({rawSize:0})),
  /raw_size_unavailable_or_too_large/);
 await assert.rejects(evaluate(mock({rawSize:RAW.length+5})),/raw_size_mismatch/);
});
test("missing raw byte stream cannot turn metadata into authenticated sender",async()=>{
 const m=mock();
 m.raw=null;
 await assert.rejects(evaluate(m),/raw_stream_required/);
});
test("no network access or outbound email delivery occurs during inspection",async()=>{
 const oldFetch=globalThis.fetch;
 let called=0;
 globalThis.fetch=()=>{called++;throw Error("no network");};
 try{
  const m=mock();
  m.forward=()=>{throw Error("no forwarding");};
  m.reply=()=>{throw Error("no replies");};
  m.setReject=()=>{throw Error("no email routing mutation");};
  const v=await evaluate(m);
  assert.equal(v.production_authorized,false);
  assert.equal(called,0);
 }finally{globalThis.fetch=oldFetch;}
});

test("verified MIME header shape produces only Reply-To CAUTION in current Trust Engine",async()=>{
 const upstream=await evaluate(mock());
 const caution=trustEngine.inspect({
  source:"external",
  from:FROM,
  reply_to:upstream.reply_to_address,
  subject:"Account update",
  body:"Please review your statement"
 });
 assert.equal(caution.status,"caution");
 assert.ok(caution.reasons.some(r=>r.code==="REPLY_TO_DIFFERS"));
 assert.equal(caution.domainAuthentication,"not_checked");
 assert.equal(caution.identityVerification,"not_verified");
 assert.equal(caution.isVerified,false);
 assert.equal(caution.isFakeProven,false);
});
test("a duplicate sender-controlled Authentication-Results value does not become provider proof",async()=>{
 const event=mock();
 event.headers.append("Authentication-Results",
  "mx.attacker.example; spf=pass; dkim=pass; dmarc=pass");
 const observation=await evaluate(event);
 assert.equal(observation.upstream_authentication_results_syntax_valid,false);
 assert.equal(observation.upstream_dmarc_observed,"not_checked");
 assert.equal(observation.live_sender_domain_verified,false);
});
