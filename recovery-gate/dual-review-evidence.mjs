/**
 * BharathLink Phase 7K — TWO-PERSON SIGNED RECOVERY REVIEW EVIDENCE.
 * Offline/test-only verifier. No production issuer or authorised reviewers
 * currently exist. DO NOT feed untrusted client data as trustedCase,
 * trustedSession or reviewer/issuer registries.
 *
 * A verified signature is REVIEW EVIDENCE ONLY, NEVER device approval.
 * This module performs no network, database, token, key-generation or writes.
 */
export const DUAL_REVIEW_DOMAIN='BHARATHLINK_DUAL_RECOVERY_REVIEW_V1';
export const REVIEW_SCOPE='FIRST_DEVICE_REVIEW_EVIDENCE_ONLY';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST=/^[a-f0-9]{64}$/;
const B64URL43=/^[A-Za-z0-9_-]{43}$/;
const B64URL86=/^[A-Za-z0-9_-]{86}$/;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const validTime=s=>typeof s==='string' && ISO.test(s) &&
  Number.isFinite(Date.parse(s)) && new Date(Date.parse(s)).toISOString()===s;
const time=s=>validTime(s)?Date.parse(s):NaN;
const uuid=s=>typeof s==='string' && UUID.test(s);
const digest=s=>typeof s==='string' && DIGEST.test(s);
const fail=code=>Object.freeze({
  status:'BLOCKED',code,reviewEvidenceChecked:false,
  deviceApproved:false,deviceTrusted:false,e2eeReady:false,
  enrollmentCommitted:false,canActivate:false
});
function rawSignature(value){
  if(typeof value!=='string'||!B64URL86.test(value))return null;
  try{
    const bin=atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(88,'='));
    if(bin.length!==64)return null;
    const raw=Uint8Array.from(bin,ch=>ch.charCodeAt(0));
    let reconstruct='';for(const n of raw)reconstruct+=String.fromCharCode(n);
    const canonical=btoa(reconstruct).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
    return canonical===value?raw:null;
  }catch{return null;}
}
function p256Key(jwk){
  return jwk!==null && typeof jwk==='object' && !Array.isArray(jwk) &&
    Object.keys(jwk).sort().join(',')==='crv,kty,x,y' &&
    jwk.kty==='EC' && jwk.crv==='P-256' &&
    B64URL43.test(jwk.x) && B64URL43.test(jwk.y);
}
/** Domain-separated, exact account+device+request+reviewer evidence.
 * Call this only after the trusted inputs are separately server-validated.
 */
export function canonicalReviewerPayload(c, signer){
  return [
    DUAL_REVIEW_DOMAIN,REVIEW_SCOPE,
    c.userId,c.sessionId,c.caseId,c.requestId,c.challengeId,c.deviceId,
    c.candidateProofId,c.issuerId,c.issuerKeyFingerprint,
    c.ecdhKeyDigest,c.signingKeyDigest,c.evidenceDigest,c.nonceDigest,
    c.ownerConsentAt,c.issuedAt,c.expiresAt,
    signer.reviewerId,signer.keyId,'REVIEW_ONLY_NOT_APPROVAL'
  ].join('\n');
}
function caseValid(c,nowMs){
  if(!c || typeof c!=='object'||Array.isArray(c))return false;
  for(const k of ['userId','sessionId','caseId','requestId','challengeId','deviceId','candidateProofId'])
    if(!uuid(c[k]))return false;
  for(const k of ['issuerKeyFingerprint','ecdhKeyDigest','signingKeyDigest','evidenceDigest','nonceDigest'])
    if(!digest(c[k]))return false;
  if(typeof c.issuerId!=='string'||!/^[-A-Za-z0-9_]{8,128}$/.test(c.issuerId))return false;
  if(c.requestStatus!=='pending'||c.challengeStatus!=='pending'||c.consumedAt!==null||
     c.candidateProofVerified!==true||c.ownerConsentVerified!==true||c.verifiedSignerCount!==0)
    return false;
  const consent=time(c.ownerConsentAt),start=time(c.issuedAt),end=time(c.expiresAt),
        reqCreated=time(c.requestCreatedAt),challengeExpires=time(c.challengeExpiresAt);
  if(![consent,start,end,reqCreated,challengeExpires].every(Number.isFinite))return false;
  return reqCreated<=consent && consent<=start && start<=nowMs && nowMs<end &&
    end-start<=300000 && reqCreated>=nowMs-900000 &&
    challengeExpires>nowMs && challengeExpires>=end &&
    c.userId!==c.deviceId && c.issuedAt!==c.expiresAt;
}
function validatedRegistry(registry,id){
  return registry instanceof Map && registry.has(id) && registry.get(id) &&
    typeof registry.get(id)==='object' && !Array.isArray(registry.get(id));
}
/** Server-only evidence verifier. A caller-controlled registry is NOT an
 * authorization; the caller MUST independently pin issuer and reviewer keys.
 */
export async function assessTwoPersonReview({
  trustedCase, trustedSession, issuerRegistry, reviewerRegistry,
  reviewerSignatures, nowMs, subtle=globalThis.crypto?.subtle
}={}){
  if(!Number.isSafeInteger(nowMs)||nowMs<0)return fail('INVALID_SERVER_TIME');
  if(!caseValid(trustedCase,nowMs))return fail('INVALID_CASE_OR_CONSENT');
  const c=trustedCase;
  if(!trustedSession || trustedSession.validatedByAuthServer!==true ||
     trustedSession.activeSessionInDatabase!==true ||
     trustedSession.userId!==c.userId || trustedSession.sessionId!==c.sessionId ||
     time(trustedSession.expiresAt)<=nowMs)return fail('SESSION_OR_ACCOUNT_MISMATCH');
  if(!validatedRegistry(issuerRegistry,c.issuerId))return fail('NO_PINNED_INDEPENDENT_ISSUER');
  const issuer=issuerRegistry.get(c.issuerId);
  if(issuer.independentlyApproved!==true||issuer.revokedAt!==null||
     issuer.suspendedAt!==null||issuer.keyFingerprint!==c.issuerKeyFingerprint||
     !validTime(issuer.validFrom)||!validTime(issuer.validUntil)||
     time(issuer.validFrom)>nowMs||time(issuer.validUntil)<=nowMs)
    return fail('ISSUER_NOT_AUTHORISED_OR_KEY_CHANGED');
  if(!Array.isArray(reviewerSignatures)||reviewerSignatures.length!==2 ||
     !(reviewerRegistry instanceof Map))
    return fail('TWO_INDEPENDENT_REVIEWERS_REQUIRED');
  const [a,b]=reviewerSignatures;
  if(!a||!b||!uuid(a.reviewerId)||!uuid(b.reviewerId) ||
     a.reviewerId===b.reviewerId || typeof a.keyId!=='string'||
     typeof b.keyId!=='string'||a.keyId===b.keyId||
     !/^[-a-zA-Z0-9_]{8,128}$/.test(a.keyId)||
     !/^[-a-zA-Z0-9_]{8,128}$/.test(b.keyId))
    return fail('REVIEWER_NOT_INDEPENDENT');
  if(!validatedRegistry(reviewerRegistry,a.reviewerId) ||
     !validatedRegistry(reviewerRegistry,b.reviewerId))
    return fail('REVIEWER_NOT_PROVISIONED');
  const x=reviewerRegistry.get(a.reviewerId),y=reviewerRegistry.get(b.reviewerId);
  if(!x.separationGroup||!y.separationGroup||x.separationGroup===y.separationGroup)
    return fail('SAME_REVIEW_AUTHORITY_GROUP');
  for(const [signature,person] of [[a,x],[b,y]]){
    if(signature.reviewerId===c.userId ||
       person.reviewerId!==signature.reviewerId ||
       person.keyId!==signature.keyId ||
       person.scope!==REVIEW_SCOPE ||
       person.role!=='independent_recovery_reviewer' ||
       person.independentlyCredentialed!==true ||
       person.active!==true || person.revokedAt!==null ||
       person.suspendedAt!==null ||
       !validTime(person.validFrom)||!validTime(person.validUntil)||
       time(person.validFrom)>nowMs||time(person.validUntil)<=nowMs ||
       !Array.isArray(person.conflictUserIds)||
       person.conflictUserIds.includes(c.userId) ||
       !p256Key(person.publicJwk))
       return fail('REVIEWER_AUTHORITY_INVALID');
  }
  if(!subtle || typeof subtle.importKey!=='function'||typeof subtle.verify!=='function')
    return fail('CRYPTO_VERIFIER_UNAVAILABLE');
  for(const [signature,person] of [[a,x],[b,y]]){
    const sig=rawSignature(signature.signatureBase64Url);
    if(!sig)return fail('MALFORMED_REVIEWER_SIGNATURE');
    try{
      const key=await subtle.importKey('jwk',
        {...person.publicJwk,ext:true,key_ops:['verify']},
        {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
      const valid=await subtle.verify({name:'ECDSA',hash:'SHA-256'},key,sig,
        new TextEncoder().encode(canonicalReviewerPayload(c,signature)));
      if(!valid)return fail('REVIEWER_SIGNATURE_MISMATCH');
    }catch{return fail('REVIEWER_SIGNATURE_MISMATCH');}
  }
  // NO nonce consumption, trust grant, device insertion or client response
  // that could be construed as authorising a first device.
  return Object.freeze({
    status:'TWO_SIGNATURES_VALID_REVIEW_EVIDENCE_ONLY',
    code:'REQUIRES_INDEPENDENT_GOVERNANCE_AND_ATOMIC_SERVER_REVIEW',
    reviewEvidenceChecked:true,
    deviceApproved:false,deviceTrusted:false,e2eeReady:false,
    enrollmentCommitted:false,canActivate:false
  });
}
