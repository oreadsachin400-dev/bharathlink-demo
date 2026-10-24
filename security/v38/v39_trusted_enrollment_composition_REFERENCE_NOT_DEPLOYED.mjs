// V39 trusted-server composition reference. NOT DEPLOYED; never import in browser.
// The pg pool and JWT verifier MUST be provisioned by a trusted server runtime.
// Requires separately reviewed V39 private schema and TEST-only migration.
// Does not implement first-device bootstrap, recovery, or legacy RPC cutover.
import {createApprovedEnrollmentHandler} from './approved_enrollment_handler_REFERENCE_NOT_DEPLOYED.mjs';
import {createV39EnrollmentAdapter} from './postgres_enrollment_adapter_v39_REFERENCE_NOT_DEPLOYED.mjs';
import {verifyAuthenticatedEnrollmentBoundary} from './verify_authenticated_enrollment_boundary.mjs';

// Export a read-only, fail-closed identity/signature gate for server integration.
// A true result is NOT enrollment authorization: DB locking and receipt are still mandatory.
export {verifyAuthenticatedEnrollmentBoundary};

export function createV39TrustedEnrollmentService({verifyAccessToken,pgPool,clock}={}) {
 if(typeof verifyAccessToken!=='function') throw new TypeError('trusted JWT verifier required');
 if(!pgPool||typeof pgPool.connect!=='function') throw new TypeError('trusted pg pool required');
 const db=createV39EnrollmentAdapter(pgPool);
 return createApprovedEnrollmentHandler({
  authenticate: async authorization=>{
   if(typeof authorization!=='string'||!authorization.startsWith('Bearer ')) return null;
   const token=authorization.slice(7);
   if (!token || token.trim()!==token || /\s/.test(token)) return null;
   // Never trust unverified JWT payload, account IDs or request-body identities.
   let verified;
   try { verified=await verifyAccessToken(token); } catch { return null; }
   if(!verified||typeof verified.sub!=='string'|| !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(verified.sub)||
      !(verified.aud==='authenticated'||(Array.isArray(verified.aud)&&verified.aud.includes('authenticated')))||
      verified.role!=='authenticated'||verified.is_anonymous===true||
      !Number.isSafeInteger(verified.exp)||verified.exp<=Math.floor(Date.now()/1000)||
      (verified.nbf!==undefined&&(!Number.isSafeInteger(verified.nbf)||verified.nbf>Math.floor(Date.now()/1000)))) return null;
   return verified.sub;
  },
  db,
  ...(clock===undefined?{}:{clock})
 });
}
