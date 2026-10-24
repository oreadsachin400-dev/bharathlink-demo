import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthenticatedChallengeIssuer} from './v39_authenticated_challenge_issuer_REFERENCE_NOT_DEPLOYED.mjs';
const accountId='11111111-1111-4111-8111-111111111111';
const body={requestId:'22222222-2222-4222-8222-222222222222',candidateDeviceId:'33333333-3333-4333-8333-333333333333'};
test('policy must approve before storage',async()=>{
 let writes=0;
 const base={authenticate:async()=>accountId,store:{insertChallengeIfAbsent:async()=>{writes++;return true;}},clock:()=>1000,random:n=>Buffer.alloc(n,1)};
 const request={authorization:'Bearer verified-token',body};
 for(const policy of [async()=>false,async()=>undefined,async()=>{throw Error('offline');}]){
  const handle=createAuthenticatedChallengeIssuer({...base,authorizeChallenge:policy});
  assert.equal((await handle(request)).ok,false);
 }
 assert.equal(writes,0);
 assert.throws(()=>createAuthenticatedChallengeIssuer(base));
});
