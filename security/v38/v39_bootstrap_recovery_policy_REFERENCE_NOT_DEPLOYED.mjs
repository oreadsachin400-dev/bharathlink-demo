// V39 reference-only decision policy. No enrollment success path, no DB writes.
// Explicitly distinguishes existing-device approval from first-device/recovery.
// An OTP, session JWT, candidate-generated key or claimed admin flag is NOT
// an independently verified authority. Do not deploy or treat as authorization.
export function classifyEnrollmentAuthority({kind,authenticatedAccountId,verifiedApprover}={}) {
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
 if (!uuid.test(authenticatedAccountId)) return Object.freeze({allowed:false,reason:'INVALID_ACCOUNT'});
 if (kind==='initial' || kind==='recovery') return Object.freeze({allowed:false,reason:'INDEPENDENT_AUTHORITY_REQUIRED'});
 if (kind!=='additional-device') return Object.freeze({allowed:false,reason:'UNSUPPORTED_ENROLLMENT'});
 if (!verifiedApprover || verifiedApprover.accountId!==authenticatedAccountId ||
     verifiedApprover.verified!==true || verifiedApprover.revoked!==false ||
     !uuid.test(verifiedApprover.deviceId))
   return Object.freeze({allowed:false,reason:'VERIFIED_APPROVER_REQUIRED'});
 // Even a verified approver cannot authorize a write without fresh signature,
 // candidate binding, atomic consumption and bypass cutover.
 return Object.freeze({allowed:false,reason:'SIGNED_APPROVAL_AND_ATOMIC_CUTOVER_REQUIRED'});
}
