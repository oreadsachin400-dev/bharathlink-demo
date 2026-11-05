import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
 assessTwoPersonReview,canonicalReviewerPayload,DUAL_REVIEW_DOMAIN,REVIEW_SCOPE
} from '../recovery-gate/dual-review-evidence.mjs';
const subtle=webcrypto.subtle;
const ids={
 user:'11111111-1111-4111-8111-111111111111',
 session:'22222222-2222-4222-8222-222222222222',
 case:'33333333-3333-4333-8333-333333333333',
 request:'44444444-4444-4444-8444-444444444444',
 challenge:'55555555-5555-4555-8555-555555555555',
 device:'66666666-6666-4666-8666-666666666666',
 proof:'77777777-7777-4777-8777-777777777777',
 r1:'88888888-8888-4888-8888-888888888888',
 r2:'99999999-9999-4999-8999-999999999999'
};
const nowMs=Date.parse('2026-11-05T17:30:00.000Z');
const at=ms=>new Date(nowMs+ms).toISOString();
const asBytes=str=>new TextEncoder().encode(str);
async function fixture(){
 const c={
  userId:ids.user,sessionId:ids.session,caseId:ids.case,
  requestId:ids.request,challengeId:ids.challenge,deviceId:ids.device,
  candidateProofId:ids.proof,issuerId:'independent-issuer-synthetic-only',
  issuerKeyFingerprint:'f'.repeat(64),
  ecdhKeyDigest:'a'.repeat(64),signingKeyDigest:'b'.repeat(64),
  evidenceDigest:'c'.repeat(64),nonceDigest:'d'.repeat(64),
  requestCreatedAt:at(-280000),ownerConsentAt:at(-120000),
  issuedAt:at(-60000),expiresAt:at(180000),challengeExpiresAt:at(240000),
  requestStatus:'pending',challengeStatus:'pending',consumedAt:null,
  candidateProofVerified:true,ownerConsentVerified:true,verifiedSignerCount:0
 };
 const session={userId:ids.user,sessionId:ids.session,validatedByAuthServer:true,
   activeSessionInDatabase:true,expiresAt:at(240000)};
 const issuerRegistry=new Map([[c.issuerId,{
   independentlyApproved:true,revokedAt:null,suspendedAt:null,
   keyFingerprint:c.issuerKeyFingerprint,
   validFrom:at(-24*3600*1000),validUntil:at(24*3600*1000)
 }]]);
 const reviewerRegistry=new Map();
 const reviewerSignatures=[];
 const signerKeys=new Map();
 for(const [index,rid] of [ids.r1,ids.r2].entries()){
   const kp=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
   const jwk=await subtle.exportKey('jwk',kp.publicKey);
   const keyId='synthetic-signing-key-'+index;
   reviewerRegistry.set(rid,{
     reviewerId:rid,keyId,scope:REVIEW_SCOPE,role:'independent_recovery_reviewer',
     independentlyCredentialed:true,active:true,revokedAt:null,suspendedAt:null,
     separationGroup:'separate-authority-'+index,
     validFrom:at(-24*3600*1000),validUntil:at(24*3600*1000),
     conflictUserIds:[],
     publicJwk:{kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y}
   });
   signerKeys.set(rid,kp.privateKey);
   reviewerSignatures.push({reviewerId:rid,keyId,signatureBase64Url:''});
 }
 for(const s of reviewerSignatures){
   const raw=await subtle.sign({name:'ECDSA',hash:'SHA-256'},signerKeys.get(s.reviewerId),
     asBytes(canonicalReviewerPayload(c,s)));
   assert.equal(raw.byteLength,64);
   s.signatureBase64Url=Buffer.from(raw).toString('base64url');
 }
 return {trustedCase:c,trustedSession:session,issuerRegistry,reviewerRegistry,
   reviewerSignatures,nowMs,subtle,signerKeys};
}
async function blocked(code,mutate){
 const args=await fixture(); mutate(args);
 const result=await assessTwoPersonReview(args);
 assert.equal(result.status,'BLOCKED');
 assert.equal(result.code,code);
 assert.equal(result.deviceApproved,false);
 assert.equal(result.canActivate,false);
 assert.equal(result.e2eeReady,false);
}
test('two independent signed reviews validate evidence ONLY, never approve a device',async()=>{
 const f=await fixture(),r=await assessTwoPersonReview(f);
 assert.equal(r.status,'TWO_SIGNATURES_VALID_REVIEW_EVIDENCE_ONLY');
 assert.equal(r.reviewEvidenceChecked,true);
 for(const key of ['deviceApproved','deviceTrusted','canActivate','e2eeReady','enrollmentCommitted'])
   assert.equal(r[key],false,key);
 assert.equal(Object.isFrozen(r),true);
 assert.match(canonicalReviewerPayload(f.trustedCase,f.reviewerSignatures[0]),
   new RegExp('^'+DUAL_REVIEW_DOMAIN+'\\n'+REVIEW_SCOPE));
});
test('missing or malformed case, no candidate possession, no consent fail closed',async()=>{
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase=null;});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.ownerConsentVerified=false;});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.requestStatus='approved';});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.challengeStatus='consumed';});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.candidateProofVerified=false;});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.verifiedSignerCount=1;});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.ecdhKeyDigest='invalid';});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.consumedAt=at(-1000);});
});
test('review time limits, expiry, and challenge lifecycle enforced',async()=>{
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.nowMs=nowMs+180001;});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.requestCreatedAt=at(-900001);});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.expiresAt=at(300000);});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.challengeExpiresAt=at(10000);});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.ownerConsentAt=at(100000);});
 await blocked('INVALID_CASE_OR_CONSENT',f=>{f.trustedCase.issuedAt='2026-02-29T00:00:00.000Z';});
});
test('session and account must match authenticated server state',async()=>{
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedSession.activeSessionInDatabase=false;});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedSession.validatedByAuthServer=false;});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedSession.userId=ids.r1;});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedSession.sessionId=ids.r1;});
 await blocked('SESSION_OR_ACCOUNT_MISMATCH',f=>{f.trustedSession.expiresAt=at(-1);});
});
test('no pinned issuer, revoked or rotated signing key rejected',async()=>{
 await blocked('NO_PINNED_INDEPENDENT_ISSUER',f=>{f.issuerRegistry=new Map();});
 await blocked('ISSUER_NOT_AUTHORISED_OR_KEY_CHANGED',f=>{
    f.issuerRegistry.get(f.trustedCase.issuerId).independentlyApproved=false;
 });
 await blocked('ISSUER_NOT_AUTHORISED_OR_KEY_CHANGED',f=>{
    f.issuerRegistry.get(f.trustedCase.issuerId).revokedAt=at(-1000);
 });
 await blocked('ISSUER_NOT_AUTHORISED_OR_KEY_CHANGED',f=>{
    f.issuerRegistry.get(f.trustedCase.issuerId).keyFingerprint='e'.repeat(64);
 });
 await blocked('ISSUER_NOT_AUTHORISED_OR_KEY_CHANGED',f=>{
    f.issuerRegistry.get(f.trustedCase.issuerId).suspendedAt=at(-1000);
 });
});
test('both reviewers are mandatory; same person, key or same authority group denied',async()=>{
 await blocked('TWO_INDEPENDENT_REVIEWERS_REQUIRED',f=>{f.reviewerSignatures.pop();});
 await blocked('REVIEWER_NOT_INDEPENDENT',f=>{f.reviewerSignatures[1].reviewerId=ids.r1;});
 await blocked('REVIEWER_NOT_INDEPENDENT',f=>{f.reviewerSignatures[1].keyId=f.reviewerSignatures[0].keyId;});
 await blocked('SAME_REVIEW_AUTHORITY_GROUP',f=>{
   f.reviewerRegistry.get(ids.r2).separationGroup=f.reviewerRegistry.get(ids.r1).separationGroup;
 });
 await blocked('REVIEWER_NOT_PROVISIONED',f=>{f.reviewerRegistry.delete(ids.r2);});
});
test('independent reviewer role, consent conflicts, revocation and scope enforced',async()=>{
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r1).active=false;});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r2).independentlyCredentialed=false;});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r1).role='friend';});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r1).scope='APPROVE_DEVICE';});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r2).revokedAt=at(-1000);});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r1).conflictUserIds=[ids.user];});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r1).validUntil=at(-1);});
 await blocked('REVIEWER_AUTHORITY_INVALID',f=>{f.reviewerRegistry.get(ids.r2).publicJwk.d='fake-private-key';});
});
test('signatures bind full account, session, challenge, device, keys, nonce and reviewer',async()=>{
 for(const mutate of [
    f=>{f.trustedCase.userId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';f.trustedSession.userId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';},
    f=>{f.trustedCase.sessionId=ids.r1;f.trustedSession.sessionId=ids.r1;},
    f=>{f.trustedCase.challengeId=ids.r2;},
    f=>{f.trustedCase.deviceId=ids.r2;},
    f=>{f.trustedCase.ecdhKeyDigest='e'.repeat(64);},
    f=>{f.trustedCase.signingKeyDigest='e'.repeat(64);},
    f=>{f.trustedCase.evidenceDigest='e'.repeat(64);},
    f=>{f.trustedCase.nonceDigest='e'.repeat(64);},
    f=>{f.trustedCase.caseId=ids.r1;},
    f=>{f.trustedCase.issuedAt=at(-50000);}
 ]) await blocked('REVIEWER_SIGNATURE_MISMATCH',mutate);
});
test('reviewer signature cannot be swapped, forged or encoded noncanonically',async()=>{
 await blocked('REVIEWER_SIGNATURE_MISMATCH',f=>{
    [f.reviewerSignatures[0].signatureBase64Url,f.reviewerSignatures[1].signatureBase64Url]=
    [f.reviewerSignatures[1].signatureBase64Url,f.reviewerSignatures[0].signatureBase64Url];
 });
 await blocked('MALFORMED_REVIEWER_SIGNATURE',f=>{f.reviewerSignatures[0].signatureBase64Url+='=';});
 await blocked('MALFORMED_REVIEWER_SIGNATURE',f=>{f.reviewerSignatures[0].signatureBase64Url='!'.repeat(86);});
 await blocked('REVIEWER_SIGNATURE_MISMATCH',f=>{
   f.reviewerRegistry.get(ids.r2).publicJwk=f.reviewerRegistry.get(ids.r1).publicJwk;
 });
});
test('missing WebCrypto and malformed now timestamp never bypass',async()=>{
 await blocked('CRYPTO_VERIFIER_UNAVAILABLE',f=>{f.subtle=null;});
 await blocked('INVALID_SERVER_TIME',f=>{f.nowMs=NaN;});
 await blocked('INVALID_SERVER_TIME',f=>{f.nowMs=-1;});
});
test('no OTP, KYC claim or caller-provided issuer key can change verdict',async()=>{
 const f=await fixture();
 f.trustedCase.otpVerified=true;
 f.trustedCase.kycStatus='verified';
 f.reviewerSignatures[0].issuerPublicJwk={kty:'EC',crv:'P-256',x:'X'.repeat(43),y:'Y'.repeat(43)};
 assert.equal((await assessTwoPersonReview(f)).canActivate,false);
 f.issuerRegistry=new Map();
 assert.equal((await assessTwoPersonReview(f)).code,'NO_PINNED_INDEPENDENT_ISSUER');
});
test('module has no network, SQL, token access, key generation, or enrollment path',()=>{
 const src=readFileSync(new URL('../recovery-gate/dual-review-evidence.mjs',import.meta.url),'utf8');
 for(const forbidden of ['fetch(', 'XMLHttpRequest','INSERT INTO','UPDATE public.',
  'register_e2ee_v2_device','bl20_commit_device_approval','privateKey',
  'generateKey(', 'service_role','localStorage.','sessionStorage.','supabase.from('])
   assert.equal(src.includes(forbidden),false,forbidden);
 assert.doesNotMatch(src,/deviceApproved:\s*true|canActivate:\s*true|e2eeReady:\s*true|enrollmentCommitted:\s*true/);
});
