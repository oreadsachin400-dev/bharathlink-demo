import test from 'node:test';
import assert from 'node:assert/strict';
import {createChallengeIssuer} from './v39_recovery_challenge_store_REFERENCE_NOT_DEPLOYED.mjs';
const ids={accountId:'11111111-1111-4111-8111-111111111111',candidateDeviceId:'22222222-2222-4222-8222-222222222222',requestId:'33333333-3333-4333-8333-333333333333'};
const deps={clock:()=>1000,random:n=>Buffer.alloc(n,7)};
test('challenge returned only after store confirms insert',async()=>{
 let saved;
 const issue=createChallengeIssuer({...deps,store:{insertChallengeIfAbsent:async row=>{saved=row;return true;}}});
 const result=await issue(ids);
 assert.equal(result.ok,true);
 assert.equal(saved.requestId,ids.requestId);
 assert.equal(saved.consumed,false);
 assert.equal(result.challenge.requestId,saved.requestId);
});
test('duplicate, rejected and failed persistence deny issuance',async()=>{
 for(const store of [
  {insertChallengeIfAbsent:async()=>false},
  {insertChallengeIfAbsent:async()=>{throw new Error('db offline');}},
  {insertChallengeIfAbsent:async()=>undefined}
 ]){
  const result=await createChallengeIssuer({...deps,store})(ids);
  assert.deepEqual(result,{ok:false,reason:'NOT_STORED'});
 }
});
test('invalid challenge binding cannot reach store',async()=>{
 let calls=0;
 const issue=createChallengeIssuer({...deps,store:{insertChallengeIfAbsent:async()=>{calls++;return true;}}});
 const result=await issue({...ids,accountId:'invalid'});
 assert.deepEqual(result,{ok:false,reason:'NOT_STORED'});
 assert.equal(calls,0);
});

test('missing issue payload fails closed without persistence',async()=>{
 let calls=0;
 const issue=createChallengeIssuer({...deps,store:{insertChallengeIfAbsent:async()=>{calls++;return true;}}});
 assert.deepEqual(await issue(),{ok:false,reason:'NOT_STORED'});
 assert.equal(calls,0);
});

test('null, arrays and scalar issue payloads fail closed without storage',async()=>{
 let calls=0;
 const issue=createChallengeIssuer({...deps,store:{insertChallengeIfAbsent:async()=>{calls++;return true;}}});
 for(const payload of [null,[],false,7,'bad']){
  assert.deepEqual(await issue(payload),{ok:false,reason:'NOT_STORED'});
 }
 assert.equal(calls,0);
});
