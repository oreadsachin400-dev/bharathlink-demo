// ISOLATED SERVER ROUTE REFERENCE — NOT DEPLOYED.
// Authentication identity must come from a verified server-side JWT lookup,
// never a JSON field supplied by the candidate device.
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';

export function createApprovedEnrollmentHandler({authenticate,db,clock=()=>Math.floor(Date.now()/1000)}) {
 if(typeof authenticate!=='function'||!db||typeof db.transaction!=='function'||typeof clock!=='function')
   throw new TypeError('trusted server dependencies required');
 return async function handleApprovedEnrollment(req) {
  try {
   if(!req||req.method!=='POST'||!req.headers||typeof req.headers.authorization!=='string'||
      !/^Bearer [A-Za-z0-9._~+\/-]+$/.test(req.headers.authorization))
     return {status:401,body:{error:'unauthorized'}};
   const accountId=await authenticate(req.headers.authorization);
   if(typeof accountId!=='string'||accountId.length===0)
     return {status:401,body:{error:'unauthorized'}};
   const body=req.body;
   if(!body||typeof body!=='object'||Array.isArray(body)||
      Object.keys(body).sort().join(',')!=='requestId,signatureBase64url'||
      typeof body.requestId!=='string'||typeof body.signatureBase64url!=='string')
     return {status:400,body:{error:'invalid request'}};
   const result=await enrollApprovedV2({requestId:body.requestId,
     signatureBase64url:body.signatureBase64url,
     authenticatedAccountId:accountId,nowSeconds:clock(),db});
   return {status:200,body:result};
  } catch {
   // Never leak existence of pending requests, accounts, or approver keys.
   return {status:403,body:{error:'enrollment denied'}};
  }
 };
}
