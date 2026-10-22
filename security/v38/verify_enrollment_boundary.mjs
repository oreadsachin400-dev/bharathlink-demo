// Isolated verification boundary. NOT deployed; never writes to Supabase.
// The trusted-key lookup and atomic DB enrollment remain server responsibilities.
import {approvalTranscript} from './approval_transcript.mjs';
import {verifyApproval} from './verify_approval.mjs';

const HEX=/^[0-9a-f]{64}$/;
export function verifyEnrollmentApproval({request, signatureBase64url, trustedAnchor, storedRequest, nowSeconds}) {
  try {
    if (!Number.isSafeInteger(nowSeconds) || !storedRequest ||
        !trustedAnchor || trustedAnchor.revoked === true ||
        trustedAnchor.verified !== true) return false;
    // All approval fields must match an authoritative stored request.
    // A caller-supplied request cannot define its own authorization target.
    const transcript=approvalTranscript(request);
    const {state, ...storedFields}=storedRequest;
    if (approvalTranscript(storedFields)!==transcript) return false;
    if (storedRequest.state!=='pending') return false;
    if (request.expiresAt<=nowSeconds || request.expiresAt>nowSeconds+600) return false;
    if (trustedAnchor.accountId!==request.accountId ||
        trustedAnchor.deviceId!==request.approverDeviceId) return false;
    if (!HEX.test(request.candidateKeySha256) || !HEX.test(request.nonceSha256)) return false;
    return verifyApproval({publicKeyJwk:trustedAnchor.publicKeyJwk,payload:transcript,signatureBase64url});
  } catch { return false; }
}
