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

test('concurrent same-request issuance returns only one challenge when store enforces atomic uniqueness',async()=>{
 const issued=new Set();
 let inserts=0;
 const store={insertChallengeIfAbsent:async row=>{
  inserts++;
  if(issued.has(row.requestId)) return false;
  issued.add(row.requestId);
  await Promise.resolve();
  return true;
 }};
 const issue=createChallengeIssuer({...deps,store});
 const results=await Promise.all(Array.from({length:12},()=>issue(ids)));
 assert.equal(results.filter(x=>x.ok===true).length,1);
 assert.equal(results.filter(x=>x.ok===false&&x.reason==='NOT_STORED').length,11);
 assert.equal(inserts,12);
});
test('issuance never returns challenge while persistence is unresolved',async()=>{
 let complete;
 const gate=new Promise(resolve=>{complete=resolve;});
 const issue=createChallengeIssuer({...deps,store:{insertChallengeIfAbsent:async()=>{await gate;return true;}}});
 let settled=false;
 const pending=issue(ids).then(value=>{settled=true;return value;});
 await Promise.resolve();
 assert.equal(settled,false);
 complete();
 assert.equal((await pending).ok,true);
});
