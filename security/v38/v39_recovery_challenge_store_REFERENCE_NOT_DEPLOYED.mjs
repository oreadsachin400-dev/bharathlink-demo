// Reference only. Not deployed. This does not authorize device recovery.
import {prepareRecoveryChallenge} from './v39_recovery_challenge_REFERENCE_NOT_DEPLOYED.mjs';
export function createChallengeIssuer({store,clock=Date.now,random}={}) {
 if(typeof store?.insertChallengeIfAbsent!=='function'||typeof clock!=='function') throw new TypeError('missing dependencies');
 return async ({accountId,candidateDeviceId,requestId})=>{
  try {
   const {challenge,serverRecord}=prepareRecoveryChallenge({
    accountId,candidateDeviceId,requestId,now:clock(),
    ...(random===undefined?{}:{random})
   });
   // Persistence must complete before the challenge is returned.
   const inserted=await store.insertChallengeIfAbsent(serverRecord);
   return inserted===true?{ok:true,challenge}:{ok:false,reason:'NOT_STORED'};
  } catch {return {ok:false,reason:'NOT_STORED'};}
 };
}
