import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyEnrollmentAuthority} from './v39_bootstrap_recovery_policy_REFERENCE_NOT_DEPLOYED.mjs';
const accountId='11111111-1111-4111-8111-111111111111';
const approver={accountId,deviceId:'22222222-2222-4222-8222-222222222222',verified:true,revoked:false};
test('first-device and recovery always require independent authority',()=>{
 for(const kind of ['initial','recovery'])
  for(const claim of [{otpVerified:true},{admin:true},{recoveryCode:'claimed'},{verified:true},approver]){
   const result=classifyEnrollmentAuthority({kind,authenticatedAccountId:accountId,verifiedApprover:claim});
   assert.deepEqual(result,{allowed:false,reason:'INDEPENDENT_AUTHORITY_REQUIRED'});
  }
});
test('additional device cannot bypass signed approval and atomic cutover',()=>{
 assert.deepEqual(classifyEnrollmentAuthority({kind:'additional-device',authenticatedAccountId:accountId,verifiedApprover:approver}),
  {allowed:false,reason:'SIGNED_APPROVAL_AND_ATOMIC_CUTOVER_REQUIRED'});
 for(const bad of [{...approver,revoked:true},{...approver,revoked:null},{...approver,verified:false},{...approver,accountId:'33333333-3333-4333-8333-333333333333'},null]){
  assert.equal(classifyEnrollmentAuthority({kind:'additional-device',authenticatedAccountId:accountId,verifiedApprover:bad}).allowed,false);
 }
});
test('invalid account and unsupported types fail closed',()=>{
 assert.equal(classifyEnrollmentAuthority({kind:'initial',authenticatedAccountId:'not-uuid'}).reason,'INVALID_ACCOUNT');
 assert.equal(classifyEnrollmentAuthority({kind:'unexpected',authenticatedAccountId:accountId}).reason,'UNSUPPORTED_ENROLLMENT');
});

test('policy cannot be bypassed with inherited or malformed approver properties',()=>{
 const forged=Object.create({accountId,deviceId:'22222222-2222-4222-8222-222222222222',verified:true,revoked:false});
 for(const kind of ['initial','recovery','additional-device']){
  const result=classifyEnrollmentAuthority({kind,authenticatedAccountId:accountId,verifiedApprover:forged});
  assert.equal(result.allowed,false);
 }
});
