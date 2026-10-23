// V39 bootstrap/recovery authorization gate — reference only, NOT DEPLOYED.
// First device and lost-device recovery cannot reuse trusted-device approval.
// This module intentionally fails closed until an independent server authority
// is implemented and reviewed. It never writes to the database.
export function authorizeInitialOrRecoveryEnrollment({kind,accountId,proof,authority}={}) {
 if(kind!=='initial'&&kind!=='recovery') throw new Error('unsupported enrollment authority');
 if(typeof accountId!=='string'||accountId.length===0) throw new Error('missing authenticated account');
 if(!authority||typeof authority.verifyIndependentProof!=='function')
  throw new Error('independent authority unavailable');
 if(!proof||typeof proof!=='object'||Array.isArray(proof))
  throw new Error('independent proof required');
 // Intentionally no allow/success path. A future implementation must verify
 // the proof server-side, enforce one-time use and rate limits, and commit
 // through a separate atomic transaction after threat-model review.
 throw new Error('initial and recovery enrollment disabled pending independent authority');
}
