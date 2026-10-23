// V39 trusted-server composition reference. NOT DEPLOYED; never import in browser.
// The pg pool and JWT verifier MUST be provisioned by a trusted server runtime.
// Requires separately reviewed V39 private schema and TEST-only migration.
// Does not implement first-device bootstrap, recovery, or legacy RPC cutover.
import {createApprovedEnrollmentHandler} from './approved_enrollment_handler_REFERENCE_NOT_DEPLOYED.mjs';
import {createV39EnrollmentAdapter} from './postgres_enrollment_adapter_v39_REFERENCE_NOT_DEPLOYED.mjs';

export function createV39TrustedEnrollmentService({verifyAccessToken,pgPool,clock}={}) {
 if(typeof verifyAccessToken!=='function') throw new TypeError('trusted JWT verifier required');
 if(!pgPool||typeof pgPool.connect!=='function') throw new TypeError('trusted pg pool required');
 const db=createV39EnrollmentAdapter(pgPool);
 return createApprovedEnrollmentHandler({
  authenticate: async authorization=>{
   if(typeof authorization!=='string'||!authorization.startsWith('Bearer ')) return null;
   const token=authorization.slice(7);
   // Never trust unverified JWT payload, account IDs or request-body identities.
   const verified=await verifyAccessToken(token);
   if(!verified||typeof verified.sub!=='string'||verified.sub.length===0||
      !(verified.aud==='authenticated'||(Array.isArray(verified.aud)&&verified.aud.includes('authenticated')))||
      verified.role!=='authenticated'||verified.is_anonymous===true) return null;
   return verified.sub;
  },
  db,
  ...(clock===undefined?{}:{clock})
 });
}
