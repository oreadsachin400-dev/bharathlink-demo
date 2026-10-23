import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizeInitialOrRecoveryEnrollment} from './v39_bootstrap_recovery_authority_REFERENCE_NOT_DEPLOYED.mjs';
test('first device and lost-device recovery are never self-approved',()=>{
 const authority={verifyIndependentProof:()=>true};
 for(const kind of ['initial','recovery']){
  assert.throws(()=>authorizeInitialOrRecoveryEnrollment({kind,accountId:'account',proof:{verified:true},authority}),/disabled pending independent authority/);
 }
});
test('missing independent authority fails closed',()=>{
 assert.throws(()=>authorizeInitialOrRecoveryEnrollment({kind:'initial',accountId:'account',proof:{}}),/independent authority unavailable/);
 assert.throws(()=>authorizeInitialOrRecoveryEnrollment({kind:'recovery',accountId:'account',proof:{},authority:{}}),/independent authority unavailable/);
});

test('claimed proof cannot bypass initial/recovery security hold',()=>{
 for(const kind of ['initial','recovery']){
  for(const proof of [{verified:true,approved:true},{otpVerified:true},{recoveryCode:'123456'},{admin:true}]){
   let called=0;
   const authority={verifyIndependentProof:()=>{called++;return true}};
   assert.throws(()=>authorizeInitialOrRecoveryEnrollment({kind,accountId:'account',proof,authority}),/disabled pending independent authority/);
   assert.equal(called,0,'reference must never invoke an untrusted authority');
  }
 }
});
