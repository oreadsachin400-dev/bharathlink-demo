import test from "node:test";
import assert from "node:assert/strict";
import {qualifiedDomainDkimVerdict} from "../../supabase/functions/bharatmail-dkim-check-test/dkim-domain-verdict.mjs";
const raw=Buffer.from([
 "From: Gmail Sender <person@gmail.com>",
 "To: inbox@example.org",
 "Subject: Test",
 "",
 "Not an actual signed message",
 ""
].join("\r\n"));
const expected="person@gmail.com";
const signature=(status="pass",fields={})=>({
 signingDomain:"gmail.com",algo:"rsa-sha256",signatureTimeValid:true,
 canonBodyLengthLimited:false,
 signingHeaders:{keys:"From: Date: Subject"},
 status:{result:status,testing:false,warnings:[]},
 ...fields
});
const base=sigs=>({headerFrom:[expected],results:sigs});
const check=(sigs,header=raw)=>qualifiedDomainDkimVerdict(base(sigs),expected,header);
test("synthetic verified cryptographic PASS is still allowed with strict domain and headers",()=>{
 const r=check([signature()]);
 assert.equal(r.dkim,"pass");
 assert.equal(r.strictly_aligned,true);
 assert.equal(r.reason,"strict_domain_signature_valid");
});
test("unverified DKIM has bounded, non-sensitive reasons for expired/failed/temporary/mismatch",()=>{
 const cases=[
  [[], "no_dkim_signature"],
  [[signature("pass",{signatureTimeValid:false})],"signature_time_invalid_or_expired"],
  [[signature("fail")],"cryptographic_signature_failed"],
  [[signature("temperror")],"signature_temporary_verification_error"],
  [[signature("neutral")],"signature_not_verifiable"],
  [[signature("policy")],"signature_policy_rejected"],
  [[signature("pass",{signingDomain:"evil.example"})],"signing_domain_mismatch"],
  [[signature("pass",{signingHeaders:{keys:"To: Subject"}})],"strong_signature_requirements_not_met"]
 ];
 for(const [sigs,reason] of cases){
   const r=check(sigs);
   assert.equal(r.dkim,"not_verified",reason);
   assert.equal(r.strictly_aligned,false,reason);
   assert.equal(r.reason,reason);
   assert.doesNotMatch(JSON.stringify(r),/gmail\.com|evil\.example|person@gmail|DKIM-Signature|headers|publicKey/);
 }
});
test("forged Authentication-Results and unsigned message are never promoted",()=>{
 const fake=Buffer.from("Authentication-Results: attacker; dkim=pass\r\n"+raw.toString());
 const r=qualifiedDomainDkimVerdict(base([]),expected,fake);
 assert.equal(r.dkim,"not_verified");
 assert.equal(r.reason,"no_dkim_signature");
});
