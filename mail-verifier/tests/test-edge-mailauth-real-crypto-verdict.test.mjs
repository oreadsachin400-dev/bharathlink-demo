import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {dkimSign} from "mailauth/lib/dkim/sign";
import {dkimVerify} from "mailauth/lib/dkim/verify";
import {
 qualifiedDomainDkimVerdict,countRawFromFields
} from "../../supabase/functions/bharatmail-dkim-check-test/dkim-domain-verdict.mjs";

const from="alerts@bank.example",domain="bank.example",selector="mail1";
const key=generateKeyPairSync("rsa",{modulusLength:2048,publicExponent:65537});
const privateKey=key.privateKey.export({format:"pem",type:"pkcs8"});
const txt="v=DKIM1; k=rsa; p="+key.publicKey.export({format:"der",type:"spki"}).toString("base64");
const now=new Date("2026-11-04T08:10:00.000Z");
const rawMessage=[
 "From: Bank Alerts <"+from+">",
 "To: reader@example.net",
 "Subject: Synthetic DKIM proof",
 "Date: Wed, 04 Nov 2026 08:00:00 +0000",
 "Message-ID: <bl-dkim-synthetic@bank.example>",
 "MIME-Version: 1.0",
 "Content-Type: text/plain; charset=utf-8",
 "",
 "This fixture was generated for a standalone local test, not a real email.",
 ""
].join("\r\n");
async function sign({domain:signingDomain=domain,base=rawMessage,maxBodyLength}={}){
 const {signatures,errors}=await dkimSign(Buffer.from(base),{
  strict:true,algorithm:"rsa-sha256",canonicalization:"relaxed/relaxed",
  signTime:new Date("2026-11-04T08:00:00Z"),
  signatureData:[{signingDomain,selector,privateKey,
   ...(maxBodyLength===undefined?{}:{maxBodyLength})}]
 });
 assert.deepEqual(errors,[]);
 assert.match(signatures,/^DKIM-Signature:/);
 return Buffer.from(signatures+base);
}
const resolver=async(name,type)=>{
 if(name!==selector+"._domainkey."+domain||type!=="TXT")
  throw Error("synthetic DNS record not present");
 return [[txt]];
};
async function verify(raw,{resolveTxt=resolver}={}){
 return dkimVerify(raw,{resolver:resolveTxt,strict:true,rejectRsaSha1:true,
  minBitLength:2048,curTime:now});
}
test("mailauth 8 genuine RSA-2048 DKIM PASSES with the actual Deno verdict helper",async()=>{
 const raw=await sign(),result=await verify(raw);
 assert.deepEqual(result.headerFrom,[from]);
 assert.ok(!Object.hasOwn(result,"fromFields"),"mailauth has no fromFields");
 assert.ok(!Object.hasOwn(result,"fromSyntax"),"mailauth has no fromSyntax");
 assert.ok(result.results.some(sig=>sig.status.result==="pass"),"DKIM cryptographic pass");
 assert.equal(countRawFromFields(raw),1);
 const verdict=qualifiedDomainDkimVerdict(result,from,raw);
 assert.equal(verdict.dkim,"pass",JSON.stringify({verdict,results:result.results.map(sig=>({
  status:sig.status?.result,signingDomain:sig.signingDomain,
  keys:sig.signingHeaders?.keys,algo:sig.algo,
  signatureTimeValid:sig.signatureTimeValid
 }))}));
 assert.equal(verdict.strictly_aligned,true);
 assert.equal(verdict.reason,"strict_domain_signature_valid");
});
test("signed message with modified body must never pass domain verdict",async()=>{
 const original=await sign(),tampered=Buffer.from(original.toString().replace("standalone local","imposter remote"));
 const result=await verify(tampered);
 assert.notEqual(qualifiedDomainDkimVerdict(result,from,tampered).dkim,"pass");
});
test("duplicate From headers fail even if underlying DKIM verification reports PASS",async()=>{
 const original=await sign();
 const dup=Buffer.from("From: second@bank.example\r\n"+original.toString());
 assert.equal(countRawFromFields(dup),2);
 const result=await verify(dup);
 assert.notEqual(qualifiedDomainDkimVerdict(result,from,dup).dkim,"pass");
});
test("an Authentication-Results: dkim=pass header does not create cryptographic proof",async()=>{
 const raw=Buffer.from("Authentication-Results: forged; dkim=pass header.d=bank.example\r\n"+rawMessage);
 assert.equal(countRawFromFields(raw),1);
 const result=await verify(raw);
 assert.notEqual(qualifiedDomainDkimVerdict(result,from,raw).dkim,"pass");
});
test("genuine signature for wrong expected sender or signing domain never passes",async()=>{
 const raw=await sign();
 const result=await verify(raw);
 assert.notEqual(qualifiedDomainDkimVerdict(result,"another@bank.example",raw).dkim,"pass");
 const different=await sign({domain:"other.example"});
 const other=await verify(different,{resolveTxt:async()=>[[txt]]});
 assert.notEqual(qualifiedDomainDkimVerdict(other,from,different).dkim,"pass");
});
test("test-only DKIM key and l= limited-body signature are not accepted as complete proof",async()=>{
 const raw=await sign();
 const withTesting=await verify(raw,{resolveTxt:async()=>[[txt+"; t=y"]]});
 assert.notEqual(qualifiedDomainDkimVerdict(withTesting,from,raw).dkim,"pass");
 const partial=await sign({maxBodyLength:20});
 const result=await verify(partial);
 assert.notEqual(qualifiedDomainDkimVerdict(result,from,partial).dkim,"pass");
});
test("missing or malformed raw From fields are not considered verified",async()=>{
 const raw=Buffer.from("Subject: fake\r\n\r\nbody\r\n");
 assert.equal(countRawFromFields(raw),0);
 assert.notEqual(qualifiedDomainDkimVerdict({headerFrom:[from],results:[]},from,raw).dkim,"pass");
 assert.equal(countRawFromFields(Buffer.from(rawMessage)),1);
});
