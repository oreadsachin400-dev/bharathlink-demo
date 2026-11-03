import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessIndependentRecovery,canonicalReviewPayload,REVIEW_ELIGIBLE,REVIEW_DOMAIN}
  from '../recovery-gate/independent-review.mjs';
const subtle=webcrypto.subtle;
const user='11111111-1111-4111-8111-111111111111', session='22222222-2222-4222-8222-222222222222';
const requestId='33333333-3333-4333-8333-333333333333', deviceId='44444444-4444-4444-8444-444444444444';
const caseId='55555555-5555-4555-8555-555555555555',r1='66666666-6666-4666-8666-666666666666',r2='77777777-7777-4777-8777-777777777777';
const nowMs=Date.parse('2026-11-03T08:00:00.000Z');
const tm=s=>new Date(nowMs+s*1000).toISOString();
const baseRequest=()=>({userId:user,requestId,deviceId,ecdhKeyDigest:'a'.repeat(64),signingKeyDigest:'b'.repeat(64),requestStatus:'pending',consumedAt:null,verifiedApproverCount:0,createdAt:tm(-180),expiresAt:tm(180)});
const baseAuth=()=>({userId:user,sessionId:session,validatedByAuthServer:true,activeSessionInDatabase:true});
const baseReview=()=>({caseId,userId:user,requestId,state:'independently_verified',evidenceDigest:'c'.repeat(64),reviewerIds:[r1,r2],ownerConsentAt:tm(-100),issuedAt:tm(-60),expiresAt:tm(120)});
function b64Url(bytes){return Buffer.from(bytes).toString('base64url');}
async function fixture(){
  const kp=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const raw=await subtle.exportKey('jwk',kp.publicKey);
  const publicKey={kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y};
  const issuerId='synthetic-independent-issuer-test-only';
  const trustedRequest=baseRequest(),trustedAuth=baseAuth(),trustedReview=baseReview();
  const payload=canonicalReviewPayload(trustedRequest,trustedAuth,trustedReview);
  const sig=new Uint8Array(await subtle.sign({name:'ECDSA',hash:'SHA-256'},kp.privateKey,new TextEncoder().encode(payload)));
  assert.equal(sig.length,64);
  return {trustedRequest,trustedAuth,trustedReview,attestation:{issuerId,signatureBase64Url:b64Url(sig)},issuerRegistry:new Map([[issuerId,publicKey]]),nowMs,subtle};
}
async function blocked(code,edit=()=>{}){const f=await fixture();edit(f);const v=await assessIndependentRecovery(f);assert.equal(v.status,'BLOCKED');assert.equal(v.code,code);assert.equal(v.deviceTrusted,false);assert.equal(v.e2eeReady,false);assert.equal(v.enrollmentCommitted,false);}
test('crypto-attested synthetic review is ONLY eligible for further manual review, never approved',async()=>{
 const f=await fixture(); const r=await assessIndependentRecovery(f);
 assert.equal(r.status,REVIEW_ELIGIBLE);assert.equal(r.deviceTrusted,false);assert.equal(r.e2eeReady,false);assert.equal(r.enrollmentCommitted,false);
 assert.match(canonicalReviewPayload(f.trustedRequest,f.trustedAuth,f.trustedReview),new RegExp('^'+REVIEW_DOMAIN+'\\n'));
});
test('no independent issuer, issuer substitution and self-asserted issuer keys rejected',async()=>{
 await blocked('NO_INDEPENDENT_TRUST_ANCHOR',f=>{f.issuerRegistry=new Map();});
 await blocked('NO_INDEPENDENT_TRUST_ANCHOR',f=>{f.attestation.issuerId='fake';f.attestation.issuerPublicJwk=f.issuerRegistry.values().next().value;});
 await blocked('MALFORMED_ATTESTATION',f=>{f.issuerRegistry.set(f.attestation.issuerId,{kty:'EC',crv:'P-256',x:'fake',y:'fake'});});
});
test('OTP login or screenshot certificate alone is never independent identity authorization',async()=>{
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.state='email_otp_authenticated';});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.state='keyprep_signer_matched';});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedAuth.activeSessionInDatabase=false;});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedAuth.validatedByAuthServer=false;});
});
test('different account, different case, different request and session rejected',async()=>{
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedAuth.userId='88888888-8888-4888-8888-888888888888';});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.requestId='88888888-8888-4888-8888-888888888888';});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.userId='88888888-8888-4888-8888-888888888888';});
 await blocked('ATTESTATION_SIGNATURE_INVALID',f=>{f.trustedAuth.sessionId='88888888-8888-4888-8888-888888888888';});
 await blocked('ATTESTATION_SIGNATURE_INVALID',f=>{f.trustedReview.caseId='88888888-8888-4888-8888-888888888888';});
});
test('tampered device, key fingerprints, evidence, reviewer, time are signed, not mutable',async()=>{
 for(const tweak of [
 f=>{f.trustedRequest.deviceId='88888888-8888-4888-8888-888888888888';},
 f=>{f.trustedRequest.ecdhKeyDigest='d'.repeat(64);},
 f=>{f.trustedRequest.signingKeyDigest='d'.repeat(64);},
 f=>{f.trustedReview.evidenceDigest='d'.repeat(64);},
 f=>{f.trustedReview.reviewerIds[1]='88888888-8888-4888-8888-888888888888';},
 f=>{f.trustedReview.issuedAt=tm(-50);}
 ])await blocked('ATTESTATION_SIGNATURE_INVALID',tweak);
});
test('expired or consumed request, bad TTL and malformed digests rejected',async()=>{
 await blocked('REQUEST_EXPIRED_OR_INVALID_TTL',f=>{f.nowMs=Date.parse(tm(181));});
 await blocked('INVALID_PENDING_REQUEST',f=>{f.trustedRequest.requestStatus='approved';});
 await blocked('INVALID_PENDING_REQUEST',f=>{f.trustedRequest.consumedAt=tm(-10);});
 await blocked('INVALID_PENDING_REQUEST',f=>{f.trustedRequest.signingKeyDigest='invalid';});
 await blocked('REQUEST_EXPIRED_OR_INVALID_TTL',f=>{f.trustedRequest.createdAt=tm(-1000);});
});
test('recovery path refuses to override existing verified approver or unknown signer count',async()=>{
 await blocked('NOT_A_FIRST_DEVICE_RECOVERY',f=>{f.trustedRequest.verifiedApproverCount=1;});
 await blocked('NOT_A_FIRST_DEVICE_RECOVERY',f=>{f.trustedRequest.verifiedApproverCount=undefined;});
});
test('requires two independent reviewers and timely explicit consent',async()=>{
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.reviewerIds=[r1];});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.reviewerIds=[r1,r1];});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.reviewerIds=[r1,user];});
 await blocked('INDEPENDENT_REVIEW_REQUIRED',f=>{f.trustedReview.ownerConsentAt=null;});
 await blocked('REVIEW_EXPIRED_OR_CONSENT_INVALID',f=>{f.trustedReview.ownerConsentAt=tm(20);});
 await blocked('REVIEW_EXPIRED_OR_CONSENT_INVALID',f=>{f.trustedReview.expiresAt=tm(-1);});
 await blocked('REVIEW_EXPIRED_OR_CONSENT_INVALID',f=>{f.trustedReview.ownerConsentAt=tm(-200);});
});
test('malformed/noncanonical/wrong issuer signatures denied',async()=>{
 await blocked('MALFORMED_ATTESTATION',f=>{f.attestation.signatureBase64Url+='=';});
 await blocked('MALFORMED_ATTESTATION',f=>{f.attestation.signatureBase64Url='!'.repeat(86);});
 const other=await fixture(),f=await fixture();
 f.issuerRegistry.set(f.attestation.issuerId,other.issuerRegistry.get(other.attestation.issuerId));
 assert.equal((await assessIndependentRecovery(f)).code,'ATTESTATION_SIGNATURE_INVALID');
});
test('code is offline and never invokes activation or database writes',()=>{
 const c=readFileSync(new URL('../recovery-gate/independent-review.mjs',import.meta.url),'utf8');
 for(const forbidden of ['fetch(', 'register_e2ee_v2_device','bl20_commit_device_approval','supabase.from(', 'INSERT INTO','UPDATE public.messaging_devices','service_role']){
  assert.equal(c.includes(forbidden),false,forbidden);
 }
});
