/**
 * Synthetic-only fixture. Generates ephemeral ECDSA private keys in CI memory.
 * Never a production issuer, user account, signed approval or device key.
 */
import {webcrypto} from 'node:crypto';
import {canonicalReviewerPayload,REVIEW_SCOPE} from '../../recovery-gate/dual-review-evidence.mjs';
const subtle=webcrypto.subtle;
const ids=Object.freeze({
 user:'11111111-1111-4111-8111-111111111111',
 session:'22222222-2222-4222-8222-222222222222',
 request:'33333333-3333-4333-8333-333333333333',
 challenge:'44444444-4444-4444-8444-444444444444',
 device:'55555555-5555-4555-8555-555555555555',
 proof:'66666666-6666-4666-8666-666666666666',
 reviewerA:'77777777-7777-4777-8777-777777777777',
 reviewerB:'88888888-8888-4888-8888-888888888888',
 intent:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 case:'99999999-9999-4999-8999-999999999999'
});
export async function syntheticReviewFixture(nowMs=Date.now()){
 const at=ms=>new Date(nowMs+ms).toISOString();
 const trustedCase={
   userId:ids.user,sessionId:ids.session,caseId:ids.case,
   requestId:ids.request,challengeId:ids.challenge,deviceId:ids.device,
   candidateProofId:ids.proof,issuerId:'synthetic-independent-issuer-review',
   issuerKeyFingerprint:'a'.repeat(64),
   ecdhKeyDigest:'b'.repeat(64),signingKeyDigest:'c'.repeat(64),
   evidenceDigest:'d'.repeat(64),nonceDigest:'7'.repeat(64),
   requestCreatedAt:at(-100000),ownerConsentAt:at(-45000),
   issuedAt:at(-30000),expiresAt:at(120000),
   challengeExpiresAt:at(180000),
   requestStatus:'pending',challengeStatus:'pending',
   consumedAt:null,candidateProofVerified:true,ownerConsentVerified:true,
   verifiedSignerCount:0
 };
 const trustedSession={userId:ids.user,sessionId:ids.session,
   validatedByAuthServer:true,activeSessionInDatabase:true,
   expiresAt:at(240000)};
 const trustedIntent={
   intentId:ids.intent,userId:ids.user,sessionId:ids.session,
   requestId:ids.request,challengeId:ids.challenge,deviceId:ids.device,
   candidateProofId:ids.proof,reviewerA:ids.reviewerA,reviewerB:ids.reviewerB,
   issuerKeySha256:'a'.repeat(64),ecdhKeySha256:'b'.repeat(64),
   signingKeySha256:'c'.repeat(64),reviewedEvidenceSha256:'d'.repeat(64)
 };
 const issuerRegistry=new Map([[trustedCase.issuerId,{
   independentlyApproved:true,revokedAt:null,suspendedAt:null,
   keyFingerprint:'a'.repeat(64),
   validFrom:at(-86400000),validUntil:at(86400000)
 }]]);
 const reviewerRegistry=new Map(),reviewerSignatures=[];
 for(const [idx,id] of [ids.reviewerA,ids.reviewerB].entries()){
   const keypair=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
   const jwk=await subtle.exportKey('jwk',keypair.publicKey);
   const keyId='synthetic-key-reviewer-'+idx;
   const descriptor={reviewerId:id,keyId,scope:REVIEW_SCOPE,
     role:'independent_recovery_reviewer',
     independentlyCredentialed:true,active:true,
     revokedAt:null,suspendedAt:null,separationGroup:'separate-'+idx,
     validFrom:at(-86400000),validUntil:at(86400000),conflictUserIds:[],
     publicJwk:{kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y}};
   reviewerRegistry.set(id,descriptor);
   const signature={reviewerId:id,keyId,signatureBase64Url:''};
   const payload=canonicalReviewerPayload(trustedCase,signature);
   signature.signatureBase64Url=Buffer.from(await subtle.sign(
     {name:'ECDSA',hash:'SHA-256'},keypair.privateKey,
     new TextEncoder().encode(payload))).toString('base64url');
   reviewerSignatures.push(signature);
 }
 return {trustedCase,trustedSession,trustedIntent,issuerRegistry,
   reviewerRegistry,reviewerSignatures,nowMs,subtle};
}
