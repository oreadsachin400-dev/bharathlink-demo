import test from "node:test";
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {assessExactDmarcWithVerifiedDkim} from "../dmarc-dkim-only.mjs";
const require=createRequire(import.meta.url);
const caution=require("../../bharatmail-trust-engine.js");

const auth=(from,resolveTxt=async()=>[['v=DMARC1; p=reject; adkim=s']])=>
 assessExactDmarcWithVerifiedDkim({from,domainDkim:"pass",strictlyAligned:true,resolveTxt});

test("a DKIM- and DMARC-authenticated lookalike sender still creates spoofing caution, never a legal-identity badge",async()=>{
 const domain=await auth("agent@bank-secure-login.example");
 const risk=caution.inspect({
  source:"external",
  from:"Bank Security Team <agent@bank-secure-login.example>",
  subject:"Bank Helpdesk Notice",
  body:"Please contact our security team."
 });
 assert.equal(domain.dmarc,"pass");
 assert.ok(risk.reasons.some(x=>x.code==="POSSIBLE_LOOKALIKE_DOMAIN"));
 assert.equal(risk.isVerified,false);
 assert.equal(risk.isFakeProven,false);
 assert.equal(risk.identityVerification,"not_verified");
 assert.equal(domain.sender_identity,"not_verified");
 assert.equal(domain.organization_authority,"not_verified");
});

test("valid Gmail domain authentication cannot make an alleged police or bank message safe",async()=>{
 const domain=await auth("alerts@gmail.com");
 const risk=caution.inspect({
  source:"external",from:"Cyber Crime Department <alerts@gmail.com>",
  subject:"URGENT payment required",body:"Transfer money immediately or your account is blocked."
 });
 assert.equal(domain.dmarc,"pass");
 assert.equal(domain.safe_to_follow_request,false);
 assert.equal(risk.status,"suspicious");
 assert.ok(risk.reasons.some(x=>x.code==="AUTHORITY_CLAIM_PUBLIC_MAIL"));
 assert.ok(risk.reasons.some(x=>x.code==="URGENT_PAYMENT"));
 assert.equal(risk.organizationAuthority,"not_verified");
 assert.equal(risk.paymentRequestVerification,"not_verified");
});

test("fabricated Authentication-Results, ID proof, trust token or verified flags never establish sender identity",async()=>{
 const risk=caution.inspect({
  source:"external",from:"Security <security@bank.example>",
  subject:"Account",body:"Your latest statement",
  headers:{"Authentication-Results":"dkim=pass; spf=pass; dmarc=pass"},
  dkim:"pass",spf:"pass",dmarc:"pass",verified:true,
  organizationVerified:true,legalNameVerified:true,identityBinding:"approved",
  evidence:{issuer:"bank",signature:"fake"}
 });
 assert.equal(risk.isVerified,false);
 assert.equal(risk.isFakeProven,false);
 assert.equal(risk.domainAuthentication,"not_checked");
 assert.equal(risk.identityVerification,"not_verified");
 assert.equal(risk.organizationAuthority,"not_verified");
 assert.equal(risk.paymentRequestVerification,"not_verified");
});

test("original MIME authentication and sender identity remain separate evidence domains",async()=>{
 const domain=await auth("notice@bank.example");
 const ordinary=caution.inspect({source:"external",from:"notice@bank.example",subject:"Hello",body:"Status"});
 assert.equal(domain.dmarc,"pass");
 assert.equal(ordinary.status,"unverified");
 assert.equal(ordinary.isVerified,false);
 assert.equal(domain.payment_beneficiary,"not_verified");
 assert.equal(domain.production_release_authorized,false);
});
