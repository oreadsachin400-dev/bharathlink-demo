'use strict';
// Server-side decision primitive ONLY. Inputs MUST be loaded from trusted DB
// under the authenticated session, with a row lock. This function never writes,
// registers a signing key, or grants device access.
const {approverEligibility}=require('./enrollment-approver-eligibility.cjs');
const {verifyApprovalSignature}=require('./enrollment-approval-verify.cjs');
function verifyEnrollmentApproval({request,approver,signingKey,authenticatedUserId,payload,signature,nowSeconds}={}){
  if(!authenticatedUserId||!request||!approver||!signingKey||!payload)return false;
  if(authenticatedUserId!==request.userId||authenticatedUserId!==approver.userId)return false;
  if(!approverEligibility({request,approver,signingKey,nowSeconds}))return false;
  if(payload.userId!==request.userId||payload.requestId!==request.requestId
    ||payload.proposedDeviceId!==request.proposedDeviceId
    ||payload.approverDeviceId!==approver.deviceId
    ||payload.challenge!==request.challenge
    ||payload.encryptionKeyHash!==request.encryptionKeyHash
    ||payload.signingKeyHash!==request.signingKeyHash
    ||payload.issuedAt!==request.createdAt||payload.expiresAt!==request.expiresAt)return false;
  if(!signingKey.publicJwk)return false;
  return verifyApprovalSignature(payload,signature,signingKey.publicJwk);
}
module.exports={verifyEnrollmentApproval};
