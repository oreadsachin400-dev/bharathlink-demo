// Reference-only enrollment coordinator. No database credentials or deployment.
// All reads MUST be from trusted server storage, never caller-supplied records.
// commitVerifiedApproval MUST perform one atomic DB transaction with locking,
// compare-and-swap of pending request, insertion of bound device keys and replay receipt.
// Never expose a public API accepting a caller-asserted 'verified' flag.
import {verifyEnrollmentApproval} from './verify_enrollment_boundary.mjs';

export async function prepareVerifiedEnrollment({requestId, signatureBase64url, repository, nowSeconds}) {
 if (typeof requestId!=='string' || !repository ||
     typeof repository.readRequest!=='function' ||
     typeof repository.readTrustedAnchor!=='function' ||
     !Number.isSafeInteger(nowSeconds)) throw new Error('invalid enrollment context');
 const storedRequest=await repository.readRequest(requestId);
 if (!storedRequest || storedRequest.requestId!==requestId || storedRequest.state!=='pending')
   throw new Error('approval unavailable');
 const anchor=await repository.readTrustedAnchor(storedRequest.accountId,storedRequest.approverDeviceId);
 const {state,...request}=storedRequest;
 if (!verifyEnrollmentApproval({request,storedRequest,trustedAnchor:anchor,signatureBase64url,nowSeconds}))
   throw new Error('approval rejected');
 // This is ONLY an ephemeral verified result; never serialize it or treat it
 // as an authorization token. Re-check key state inside the atomic finalizer.
 return Object.freeze({requestId,accountId:request.accountId,
  candidateDeviceId:request.candidateDeviceId,approverDeviceId:request.approverDeviceId,
  candidateKeySha256:request.candidateKeySha256,nonceSha256:request.nonceSha256,
  expiresAt:request.expiresAt});
}
