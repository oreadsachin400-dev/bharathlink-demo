// ISOLATED reference service, NOT deployed. All database operations below
// must be implemented in ONE real transaction by a trusted backend adapter.
// No caller can supply a verified flag or pre-verified request.
import {verifyEnrollmentApproval} from './verify_enrollment_boundary.mjs';
import {candidateKeyDigest} from './candidate_key_digest.mjs';

export async function enrollApprovedV2({requestId,signatureBase64url,authenticatedAccountId,nowSeconds,db}) {
 if (typeof requestId!=='string'||typeof signatureBase64url!=='string'||
     typeof authenticatedAccountId!=='string'||!Number.isSafeInteger(nowSeconds)||
     !db||typeof db.transaction!=='function') throw new Error('invalid enrollment');
 return db.transaction(async tx=>{
  // Adapter MUST lock the request and approver anchor until COMMIT.
  if (typeof tx.lockPendingRequest!=='function'||typeof tx.lockTrustedAnchor!=='function'||
      typeof tx.insertV2Device!=='function'||typeof tx.consumeRequest!=='function')
    throw new Error('unsafe transaction adapter');
  const stored=await tx.lockPendingRequest(requestId);
  if(!stored||stored.accountId!==authenticatedAccountId||stored.state!=='pending')
    throw new Error('request unavailable');
  const anchor=await tx.lockTrustedAnchor(stored.accountId,stored.approverDeviceId);
  if(!anchor||anchor.revoked||anchor.verified!==true||
     anchor.accountId!==stored.accountId||anchor.deviceId!==stored.approverDeviceId)
    throw new Error('approver unavailable');
  const {state,signingPublicKey,curve25519PublicKey,...request}=stored;
  if(typeof signingPublicKey!=='string'||typeof curve25519PublicKey!=='string')
    throw new Error('missing candidate keys');
  const digest=candidateKeyDigest({signingPublicKey,curve25519PublicKey});
  if(digest!==request.candidateKeySha256) throw new Error('candidate key mismatch');
  if(!verifyEnrollmentApproval({request,storedRequest:{...request,state},
      trustedAnchor:anchor,signatureBase64url,nowSeconds}))
    throw new Error('approval rejected');
  // Both writes MUST be in same transaction; uniqueness and one-time
  // consumption MUST be enforced by database constraints.
  await tx.insertV2Device({deviceId:request.candidateDeviceId,userId:request.accountId,
    signingPublicKey,curve25519PublicKey,protocolVersion:2});
  const consumed=await tx.consumeRequest({requestId:request.requestId,
    accountId:request.accountId,candidateDeviceId:request.candidateDeviceId,
    candidateKeySha256:digest});
  if(consumed!==true) throw new Error('request consumption failed');
  return {deviceId:request.candidateDeviceId};
 });
}
