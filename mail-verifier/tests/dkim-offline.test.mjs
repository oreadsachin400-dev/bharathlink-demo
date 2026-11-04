import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {verifyOriginalMimeDkim} from "../verify-original-dkim.mjs";

const DOMAIN="bank.example";
const from="Security Team <alerts@bank.example>";
const msg=[
  "From: "+from,
  "To: reader@example.net",
  "Subject: Monthly statement",
  "Date: Wed, 4 Nov 2026 08:00:00 +0000",
  "Message-ID: <synthetic-1@bank.example>",
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Statement reference is 0001. This is a synthetic email.",
  ""
].join("\r\n");
const key=generateKeyPairSync("rsa",{modulusLength:2048,publicExponent:0x10001});
const keyText=key.privateKey.export({format:"pem",type:"pkcs8"});
const dkimTxt="v=DKIM1; k=rsa; p="+key.publicKey.export({format:"der",type:"spki"}).toString("base64");
const wrong=generateKeyPairSync("rsa",{modulusLength:2048,publicExponent:0x10001});
const wrongTxt="v=DKIM1; k=rsa; p="+wrong.publicKey.export({format:"der",type:"spki"}).toString("base64");
async function sign({domain=DOMAIN,base=msg,selector="key1"}={}){
 const result=await dkimSign(Buffer.from(base),{
   canonicalization:"relaxed/relaxed",
   algorithm:"rsa-sha256",
   strict:true,
   signTime:new Date("2026-11-04T08:00:00Z"),
   signatureData:[{signingDomain:domain,selector,privateKey:keyText}]
 });
 assert.equal(result.errors.length,0,JSON.stringify(result.errors?.map(x=>x.err?.message)));
 assert.ok(result.signatures.startsWith("DKIM-Signature:"));
 return Buffer.concat([Buffer.from(result.signatures),Buffer.from(base)]);
}
function resolver({txt=dkimTxt, fail=false}={}){
 const requests=[];
 const resolveTxt=async(name,type)=>{
   requests.push({name,type});
   if(fail)throw Error("DNS offline");
   if(type!=="TXT"||name!=="key1._domainkey.bank.example")throw Error("No fixture DNS record");
   return [[txt]];
 };
 return {requests,resolveTxt};
}
const now=new Date("2026-11-04T08:02:00Z");

test("genuine RSA-2048 DKIM signature checks original MIME and injected DNS TXT record",async()=>{
 const signed=await sign();const dns=resolver();
 const r=await verifyOriginalMimeDkim(signed,{expectedFrom:from,resolveTxt:dns.resolveTxt,now});
 assert.equal(r.dkim,"pass",JSON.stringify(r));
 assert.equal(r.alignedStrict,true);
 assert.equal(r.signing_domain,DOMAIN);
 assert.equal(r.selector,"key1");
 assert.match(r.raw_sha256,/^[0-9a-f]{64}$/);
 assert.ok(dns.requests.some(x=>x.name==="key1._domainkey.bank.example"&&x.type==="TXT"));
 assert.equal(r.sender_identity,"not_verified");
 assert.equal(r.organizational_authority,"not_verified");
 assert.equal(r.payment_request,"not_verified");
 assert.equal(r.spf,"not_checked");
 assert.equal(r.dmarc,"not_checked");
 assert.equal(r.verified_sender,false);
});
test("mutating body after a valid DKIM signature fails in strict mode",async()=>{
 const signed=await sign();
 const changed=Buffer.from(signed.toString().replace("reference is 0001","reference is 9999"));
 assert.notDeepEqual(signed,changed);
 const r=await verifyOriginalMimeDkim(changed,{expectedFrom:from,resolveTxt:resolver().resolveTxt,now});
 assert.notEqual(r.dkim,"pass",JSON.stringify(r));
 assert.equal(r.alignedStrict,false);
});
test("untrusted replacement DNS key cannot verify the genuine signature",async()=>{
 const r=await verifyOriginalMimeDkim(await sign(),{expectedFrom:from,
   resolveTxt:resolver({txt:wrongTxt}).resolveTxt,now});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.verified_sender,false);
});
test("unauthenticated Authentication-Results header cannot fabricate a DKIM success",async()=>{
 const body=Buffer.from("Authentication-Results: attacker; dkim=pass header.d=bank.example\r\n"+msg);
 const r=await verifyOriginalMimeDkim(body,{expectedFrom:from,resolveTxt:resolver().resolveTxt,now});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.alignedStrict,false);
});
test("signing an unrelated domain never grants an aligned pass for expected From",async()=>{
 const signed=await sign({domain:"unrelated.example"});
 const r=await verifyOriginalMimeDkim(signed,{
   expectedFrom:from,resolveTxt:async(name,type)=>[[dkimTxt]],now});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.alignedStrict,false);
});
test("changing claimed sender while keeping original DKIM signature fails expected raw From binding",async()=>{
 const r=await verifyOriginalMimeDkim(await sign(),{
  expectedFrom:"Someone Else <else@bank.example>",resolveTxt:resolver().resolveTxt,now
 });
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.reason,"invalid_or_mismatched_from");
});
test("multiple raw From headers cannot be used as ambiguous authors",async()=>{
 const raw=Buffer.from("From: admin@bank.example\r\n"+(await sign()).toString());
 const r=await verifyOriginalMimeDkim(raw,{expectedFrom:from,resolveTxt:resolver().resolveTxt,now});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.alignedStrict,false);
});
test("DKIM is not checked without a deliberately injected DNS resolver",async()=>{
 await assert.rejects(verifyOriginalMimeDkim(await sign(),{expectedFrom:from,now}),
   /independent_dns_resolver_required/);
});
test("reject oversized raw MIME and malformed sender input before any DNS access",async()=>{
 const dns=resolver();
 await assert.rejects(verifyOriginalMimeDkim(Buffer.alloc(5*1024*1024+1),{
   expectedFrom:from,resolveTxt:dns.resolveTxt,now
 }),/raw_mime_size_out_of_range/);
 await assert.rejects(verifyOriginalMimeDkim(await sign(),{
   expectedFrom:"evil@example.com\r\nX-Hacked: yes",resolveTxt:dns.resolveTxt,now
 }),/invalid_from/);
 assert.equal(dns.requests.length,0);
});
test("DNS outage cannot produce a DKIM pass or safe status",async()=>{
 const r=await verifyOriginalMimeDkim(await sign(),{
   expectedFrom:from,resolveTxt:resolver({fail:true}).resolveTxt,now
 });
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.verified_sender,false);
});
test("a DKIM signature covering only an l= body prefix does not authenticate appended instructions",async()=>{
 const signedLimited=await dkimSign(Buffer.from(msg),{
   strict:true,algorithm:"rsa-sha256",canonicalization:"relaxed/relaxed",
   signTime:new Date("2026-11-04T08:00:00Z"),
   signatureData:[{signingDomain:DOMAIN,selector:"key1",privateKey:keyText,maxBodyLength:20}]
 });
 assert.equal(signedLimited.errors.length,0);
 const received=Buffer.from(signedLimited.signatures+msg+"\r\nSEND MONEY NOW\r\n");
 const r=await verifyOriginalMimeDkim(received,{expectedFrom:from,resolveTxt:resolver().resolveTxt,now});
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.alignedStrict,false);
});
test("DKIM public DNS key marked testing-only is not elevated to a qualified domain pass",async()=>{
 const r=await verifyOriginalMimeDkim(await sign(),{
   expectedFrom:from,resolveTxt:resolver({txt:dkimTxt+"; t=y"}).resolveTxt,now
 });
 assert.notEqual(r.dkim,"pass");
 assert.equal(r.verified_sender,false);
});
test("all mail trust dimensions remain separate after a domain pass",async()=>{
 const r=await verifyOriginalMimeDkim(await sign(),{
   expectedFrom:from,resolveTxt:resolver().resolveTxt,now
 });
 assert.equal(r.dkim,"pass",JSON.stringify(r));
 for(const key of ["sender_identity","organizational_authority","payment_request"])
   assert.equal(r[key],"not_verified");
 assert.equal(r.spf,"not_checked");assert.equal(r.dmarc,"not_checked");
});
