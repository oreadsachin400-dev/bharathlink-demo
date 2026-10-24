import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthenticatedChallengeIssuer} from './v39_authenticated_challenge_issuer_REFERENCE_NOT_DEPLOYED.mjs';
const accountId='11111111-1111-4111-8111-111111111111';
const body={requestId:'22222222-2222-4222-8222-222222222222',candidateDeviceId:'33333333-3333-4333-8333-333333333333'};
const valid={authorization:'Bearer server-verified-token',body};
test('trusted authenticated account is bound to persisted challenge',async()=>{
 let persisted;
 const handle=createAuthenticatedChallengeIssuer({
  authorizeChallenge:async()=>true,
  authenticate:async()=>accountId,store:{insertChallengeIfAbsent:async row=>{persisted=row;return true;}},
  clock:()=>1000,random:n=>Buffer.alloc(n,1)});
 const result=await handle(valid);
 assert.equal(result.ok,true);
 assert.equal(result.challenge.accountId,accountId);
 assert.equal(persisted.accountId,accountId);
});
test('unverified identity, injected account, malformed auth cannot issue',async()=>{
 let authCalls=0,storeCalls=0;
 const handle=createAuthenticatedChallengeIssuer({
  authorizeChallenge:async()=>true,
  authenticate:async()=>{authCalls++;return null;},
  store:{insertChallengeIfAbsent:async()=>{storeCalls++;return true;}},
  clock:()=>1000,random:n=>Buffer.alloc(n,1)});
 for(const input of [
  valid,{...valid,body:{...body,accountId}},
  {authorization:'Bearer bad token',body},null,{}, {authorization:'Bearer ok',body:null}
 ]){
  const result=await handle(input);
  assert.equal(result.ok,false);
 }
 assert.equal(storeCalls,0);
 assert.equal(authCalls,1);
});
test('client supplied account cannot override trusted identity',async()=>{
 let storeCalls=0;
 const handle=createAuthenticatedChallengeIssuer({
  authorizeChallenge:async()=>true,
  authenticate:async()=>accountId,
  store:{insertChallengeIfAbsent:async()=>{storeCalls++;return true;}},
  clock:()=>1000,random:n=>Buffer.alloc(n,1)});
 const result=await handle({...valid,body:{...body,accountId:'44444444-4444-4444-8444-444444444444'}});
 assert.equal(result.ok,false);
 assert.equal(storeCalls,0);
});

test('invalid request UUIDs never reach policy or storage',async()=>{
 let policyCalls=0,storageCalls=0;
 const handle=createAuthenticatedChallengeIssuer({
  authenticate:async()=>accountId,
  authorizeChallenge:async()=>{policyCalls++;return true;},
  store:{insertChallengeIfAbsent:async()=>{storageCalls++;return true;}},
  clock:()=>1000,random:n=>Buffer.alloc(n,1)
 });
 for(const invalid of [
  {candidateDeviceId:'not-a-uuid',requestId:body.requestId},
  {candidateDeviceId:body.candidateDeviceId,requestId:'not-a-uuid'},
  {candidateDeviceId:null,requestId:body.requestId},
  {candidateDeviceId:body.candidateDeviceId,requestId:null}
 ]){
  assert.deepEqual(await handle({authorization:valid.authorization,body:invalid}),
   {ok:false,reason:'REQUEST_DENIED'});
 }
 assert.equal(policyCalls,0);
 assert.equal(storageCalls,0);
});
