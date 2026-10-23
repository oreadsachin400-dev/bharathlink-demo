// TEST-only reference; no network or database writes. Fail closed.
// This wrapper binds a verified JWT subject to the stored enrollment account.
// The underlying signature verifier checks canonical transcript and trusted anchor.
import {verifyEnrollmentApproval} from './verify_enrollment_boundary.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function verifyAuthenticatedEnrollmentBoundary(input={}) {
  const {authenticatedAccountId, request, storedRequest, trustedAnchor}=input;
  if (typeof authenticatedAccountId!=='string' ||
      !UUID.test(authenticatedAccountId) ||
      !request || !storedRequest || !trustedAnchor ||
      request.accountId!==authenticatedAccountId ||
      storedRequest.accountId!==authenticatedAccountId ||
      trustedAnchor.accountId!==authenticatedAccountId) return false;
  return verifyEnrollmentApproval(input);
}
