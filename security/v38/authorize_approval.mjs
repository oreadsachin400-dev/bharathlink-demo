// Offline-only trusted key lookup and one-use approval reference. Not a database finalizer.
import {approvalTranscript} from './approval_transcript.mjs';
import {verifyApproval} from './verify_approval.mjs';
export function authorizeApproval({request, signatureBase64url, trustedKeys, consumedRequests, nowSeconds}) {
  if (!(trustedKeys instanceof Map) || !(consumedRequests instanceof Set) ||
      !Number.isSafeInteger(nowSeconds)) return false;
  try {
    const payload=approvalTranscript(request);
    if (request.expiresAt<=nowSeconds || request.expiresAt>nowSeconds+600) return false;
    if (consumedRequests.has(request.requestId)) return false;
    const record=trustedKeys.get(request.approverDeviceId);
    if (!record || record.accountId!==request.accountId || record.revoked===true ||
        record.verified!==true || !record.publicKeyJwk) return false;
    if (!verifyApproval({publicKeyJwk:record.publicKeyJwk,payload,signatureBase64url})) return false;
    // Reference only: atomicity is NOT guaranteed by Set; production must use DB unique constraint + transaction.
    consumedRequests.add(request.requestId);
    return true;
  } catch { return false; }
}
