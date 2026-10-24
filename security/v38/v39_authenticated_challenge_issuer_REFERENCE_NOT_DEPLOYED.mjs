// Reference-only trusted-server boundary. NOT DEPLOYED.
// The account identity is derived from a trusted authentication callback,
// never from the client request body.
import {createChallengeIssuer} from './v39_recovery_challenge_store_REFERENCE_NOT_DEPLOYED.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function createAuthenticatedChallengeIssuer({authenticate,store,clock,random,authorizeChallenge}={}) {
 if(typeof authenticate!=='function') throw new TypeError('TRUSTED_AUTHENTICATOR_REQUIRED');
 if(typeof authorizeChallenge!=='function') throw new TypeError('TRUSTED_CHALLENGE_POLICY_REQUIRED');
 const issue=createChallengeIssuer({store,...(clock===undefined?{}:{clock}),...(random===undefined?{}:{random})});
 return async function handle(request={}) {
  try {
   if(!request||typeof request!=='object'||Array.isArray(request)) return {ok:false,reason:'REQUEST_DENIED'};
   const {authorization,body}=request;
   if(typeof authorization!=='string'||!/^Bearer [A-Za-z0-9._~+\/-]+$/.test(authorization)||
      !body||typeof body!=='object'||Array.isArray(body)||
      Object.keys(body).sort().join(',')!=='candidateDeviceId,requestId') {
    return {ok:false,reason:'REQUEST_DENIED'};
   }
   const accountId=await authenticate(authorization);
   if(typeof accountId!=='string'||!UUID.test(accountId)) return {ok:false,reason:'REQUEST_DENIED'};
   // The server policy must enforce rate limits, abuse controls and request ownership.
   // Any result other than explicit true fails closed before storage is touched.
   if(await authorizeChallenge({accountId,candidateDeviceId:body.candidateDeviceId,requestId:body.requestId})!==true)
    return {ok:false,reason:'REQUEST_DENIED'};
   return await issue({accountId,candidateDeviceId:body.candidateDeviceId,requestId:body.requestId});
  } catch {return {ok:false,reason:'REQUEST_DENIED'};}
 };
}
