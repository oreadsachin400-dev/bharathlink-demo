/**
 * BharathLink Phase 7M — synthetic cryptographic review → evidence ledger bridge.
 *
 * OFFLINE INTEGRATION REFERENCE ONLY. No database client, service-role key,
 * network request, writable storage, device trust grant or E2EE key operation.
 * All trusted* objects and registries MUST originate from an independently
 * validated server source. Client-submitted lookalikes are NOT authoritative.
 * No real issuer/reviewer root has been provisioned; never deploy this.
 */
import {assessTwoPersonReview,canonicalReviewerPayload}
  from './dual-review-evidence.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX=/^[a-f0-9]{64}$/;
const safeId=s=>typeof s==='string'&&UUID.test(s);
const hash=s=>typeof s==='string'&&HEX.test(s);
const denied=code=>Object.freeze({
  status:'BLOCKED',code,reviewEvidencePrepared:false,
  deviceApproved:false,deviceTrusted:false,e2eeReady:false,
  enrollmentCommitted:false,canActivate:false
});
function decodeSignature(encoded){
  if(typeof encoded!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(encoded))return null;
  try{
    const binary=atob(encoded.replace(/-/g,'+').replace(/_/g,'/').padEnd(88,'='));
    if(binary.length!==64)return null;
    const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
    const canonical=btoa(String.fromCharCode(...bytes))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
    return canonical===encoded?bytes:null;
  }catch{return null;}
}
async function sha256Hex(bytes,subtle){
  const digest=await subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
}
function publicP256DigestInput(k){
  if(!k||typeof k!=='object'||Array.isArray(k)||
    Object.keys(k).sort().join(',')!=='crv,kty,x,y' ||
    k.kty!=='EC'||k.crv!=='P-256'||!/^[-_A-Za-z0-9]{43}$/.test(k.x)||
    !/^[-_A-Za-z0-9]{43}$/.test(k.y))return null;
  return new TextEncoder().encode([k.kty,k.crv,k.x,k.y].join('\n'));
}
function matchesIntent(c,t,sigs){
  if(!c||!t||!Array.isArray(sigs)||sigs.length!==2 ||
     !safeId(t.intentId)||!safeId(t.userId)||!safeId(t.sessionId)||
     !safeId(t.requestId)||!safeId(t.challengeId)||!safeId(t.deviceId)||
     !safeId(t.candidateProofId)||!safeId(t.reviewerA)||!safeId(t.reviewerB) ||
     ![t.issuerKeySha256,t.ecdhKeySha256,t.signingKeySha256,
       t.reviewedEvidenceSha256].every(hash))return false;
  return [
    [c.userId,t.userId],[c.sessionId,t.sessionId],
    [c.requestId,t.requestId],[c.challengeId,t.challengeId],
    [c.deviceId,t.deviceId],[c.candidateProofId,t.candidateProofId],
    [c.issuerKeyFingerprint,t.issuerKeySha256],
    [c.ecdhKeyDigest,t.ecdhKeySha256],
    [c.signingKeyDigest,t.signingKeySha256],
    [c.evidenceDigest,t.reviewedEvidenceSha256],
    [sigs[0]?.reviewerId,t.reviewerA],
    [sigs[1]?.reviewerId,t.reviewerB]
  ].every(([a,b])=>a===b);
}

/**
 * Prepare evidence-only parameters suitable for the PRIVATE Phase7L ledger
 * in a disposable PostgreSQL test. This function NEVER writes them itself.
 * Valid cryptographic signatures are only one prerequisite for real recovery.
 */
export async function prepareVerifiedLedgerEvidence({
  trustedCase, trustedSession, trustedIntent, issuerRegistry,
  reviewerRegistry, reviewerSignatures,nowMs,
  subtle=globalThis.crypto?.subtle
}={}){
  if(!matchesIntent(trustedCase,trustedIntent,reviewerSignatures))
    return denied('GOVERNANCE_INTENT_BINDING_MISMATCH');
  if(!subtle||typeof subtle.digest!=='function')
    return denied('CRYPTO_DIGEST_UNAVAILABLE');

  const verified=await assessTwoPersonReview({
    trustedCase,trustedSession,issuerRegistry,reviewerRegistry,
    reviewerSignatures,nowMs,subtle
  });
  if(verified.status!=='TWO_SIGNATURES_VALID_REVIEW_EVIDENCE_ONLY'||
     verified.reviewEvidenceChecked!==true||
     verified.canActivate!==false)
    return denied('REVIEW_SIGNATURES_NOT_VERIFIED');

  const [a,b]=reviewerSignatures;
  const pair=[[a,reviewerRegistry.get(a.reviewerId)],
              [b,reviewerRegistry.get(b.reviewerId)]];
  const digests=[];
  try{
    for(const [signature,person] of pair){
      const keyBytes=publicP256DigestInput(person?.publicJwk);
      const sigBytes=decodeSignature(signature.signatureBase64Url);
      if(!keyBytes||!sigBytes)return denied('REVIEW_SIGNER_MATERIAL_INVALID');
      digests.push(Object.freeze({
        key:await sha256Hex(keyBytes,subtle),
        signature:await sha256Hex(sigBytes,subtle),
        payload:await sha256Hex(
          new TextEncoder().encode(canonicalReviewerPayload(trustedCase,signature)),subtle)
      }));
    }
  }catch{return denied('REVIEW_DIGEST_UNAVAILABLE');}
  if(digests[0].key===digests[1].key||
     digests[0].signature===digests[1].signature||
     digests[0].payload===digests[1].payload)
    return denied('DUPLICATE_REVIEWER_EVIDENCE');

  // Exact order expected by Phase7L stage_review_evidence(). No SQL call.
  const parameters=Object.freeze([
    trustedIntent.intentId,digests[0].key,digests[1].key,
    digests[0].signature,digests[1].signature,
    digests[0].payload,digests[1].payload,
    trustedCase.nonceDigest,trustedCase.expiresAt
  ]);
  return Object.freeze({
    status:'REVIEW_EVIDENCE_PREPARED_ONLY',
    reviewEvidencePrepared:true,parameters,
    deviceApproved:false,deviceTrusted:false,e2eeReady:false,
    enrollmentCommitted:false,canActivate:false
  });
}
