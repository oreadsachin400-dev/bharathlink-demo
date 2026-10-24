// V39 independent recovery gate: REFERENCE ONLY, NOT DEPLOYED.
// No JWT, OTP, self-attestation or client-provided "verified" flag is authority.
// verifyAuthorityReceipt MUST be an independently audited trusted-server verifier
// with issuer authentication, revocation, nonce binding and replay protection.
// Even a positive result here NEVER enrolls a device or consumes a challenge.
import {validateRecoveryChallenge} from './v39_recovery_challenge_validation_REFERENCE_NOT_DEPLOYED.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export async function assessIndependentRecovery({challenge,serverRecord,authenticatedAccountId,authorityReceipt,verifyAuthorityReceipt,now=Date.now()}={}) {
 const deny=reason=>Object.freeze({allowed:false,reason});
 if(typeof verifyAuthorityReceipt!=='function') return deny('INDEPENDENT_VERIFIER_REQUIRED');
 if(!validateRecoveryChallenge({challenge,serverRecord,authenticatedAccountId,now}))
   return deny('INVALID_CHALLENGE');
 if(!authorityReceipt||typeof authorityReceipt!=='object'||Array.isArray(authorityReceipt))
   return deny('INDEPENDENT_RECEIPT_REQUIRED');
 // Never take authority or account identity from the untrusted receipt itself.
 const expected=Object.freeze({accountId:authenticatedAccountId,
   candidateDeviceId:challenge.candidateDeviceId,requestId:challenge.requestId,
   nonceSha256:serverRecord.nonceSha256,expiresAt:serverRecord.expiresAt});
 let verified;
 try {verified=await verifyAuthorityReceipt(authorityReceipt,expected);}
 catch {return deny('INDEPENDENT_VERIFICATION_FAILED');}
 // Verifier result is still insufficient without durable transactional replay guard.
 if(verified!==true) return deny('INDEPENDENT_VERIFICATION_FAILED');
 return deny('ATOMIC_AUTHORITY_CONSUMPTION_REQUIRED');
}
