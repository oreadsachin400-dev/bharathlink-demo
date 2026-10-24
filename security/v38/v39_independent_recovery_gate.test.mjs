import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareRecoveryChallenge} from './v39_recovery_challenge_REFERENCE_NOT_DEPLOYED.mjs';
import {assessIndependentRecovery} from './v39_independent_recovery_gate_REFERENCE_NOT_DEPLOYED.mjs';
const ids={accountId:'11111111-1111-4111-8111-111111111111',candidateDeviceId:'22222222-2222-4222-8222-222222222222',requestId:'33333333-3333-4333-8333-333333333333'};
function fixture(){const {challenge,serverRecord}=prepareRecoveryChallenge({...ids,now:1000,random:n=>Buffer.alloc(n,17)});return {challenge,serverRecord,authenticatedAccountId:ids.accountId,authorityReceipt:{token:'opaque'},now:2000};}
test('missing independent verifier and forged claims fail closed',async()=>{
 const f=fixture();
 assert.equal((await assessIndependentRecovery(f)).reason,'INDEPENDENT_VERIFIER_REQUIRED');
 for(const authorityReceipt of [null,undefined,'OTP',[],true]){
  const result=await assessIndependentRecovery({...f,authorityReceipt,verifyAuthorityReceipt:async()=>true});
  assert.equal(result.allowed,false);
 }
});
test('verified receipt is still not authorization until atomic consumption',async()=>{
 const f=fixture();let calls=0;
 const result=await assessIndependentRecovery({...f,verifyAuthorityReceipt:async(receipt,expected)=>{
  calls++;assert.equal(receipt,f.authorityReceipt);
  assert.equal(expected.accountId,ids.accountId);
  assert.equal(expected.candidateDeviceId,ids.candidateDeviceId);
  assert.equal(expected.requestId,ids.requestId);
  assert.equal(expected.nonceSha256,f.serverRecord.nonceSha256);
  return true;
 }});
 assert.equal(calls,1);
 assert.deepEqual(result,{allowed:false,reason:'ATOMIC_AUTHORITY_CONSUMPTION_REQUIRED'});
});
test('invalid challenge prevents independent verifier call',async()=>{
 const f=fixture();let calls=0;
 for(const patch of [{now:301000},{authenticatedAccountId:'44444444-4444-4444-8444-444444444444'},
 {serverRecord:{...f.serverRecord,consumed:true}},
 {challenge:{...f.challenge,nonce:Buffer.alloc(32,18).toString('base64')}}]){
  const result=await assessIndependentRecovery({...f,...patch,verifyAuthorityReceipt:async()=>{calls++;return true;}});
  assert.deepEqual(result,{allowed:false,reason:'INVALID_CHALLENGE'});
 }
 assert.equal(calls,0);
});
test('rejected and throwing authority verifier fail closed',async()=>{
 const f=fixture();
 for(const verifyAuthorityReceipt of [async()=>false,async()=>({verified:true}),async()=>{throw Error('provider unavailable');}]){
  const result=await assessIndependentRecovery({...f,verifyAuthorityReceipt});
  assert.deepEqual(result,{allowed:false,reason:'INDEPENDENT_VERIFICATION_FAILED'});
 }
});
