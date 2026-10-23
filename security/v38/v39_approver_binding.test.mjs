import test from 'node:test';
import assert from 'node:assert/strict';
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';

const ACCOUNT='11111111-1111-4111-8111-111111111111';
const APPROVER='22222222-2222-4222-8222-222222222222';
const request={
 requestId:'33333333-3333-4333-8333-333333333333',accountId:ACCOUNT,
 candidateDeviceId:'44444444-4444-4444-8444-444444444444',
 approverDeviceId:APPROVER,state:'pending',
 signingPublicKey:'candidate-signing',curve25519PublicKey:'candidate-encryption',
 candidateKeySha256:'irrelevant-for-mismatch'
};
for (const [name,anchor] of [
 ['cross-account approver',{accountId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',deviceId:APPROVER,verified:true,revoked:false}],
 ['wrong-device approver',{accountId:ACCOUNT,deviceId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',verified:true,revoked:false}],
 ['unverified approver',{accountId:ACCOUNT,deviceId:APPROVER,verified:false,revoked:false}],
 ['revoked approver',{accountId:ACCOUNT,deviceId:APPROVER,verified:true,revoked:true}]
]){
 test(name+' cannot insert or consume enrollment',async()=>{
  let writes=0;
  const db={transaction:async fn=>fn({
   lockPendingRequest:async()=>request,
   lockTrustedAnchor:async()=>anchor,
   insertV2Device:async()=>{writes++},
   consumeRequest:async()=>{writes++;return true}
  })};
  await assert.rejects(enrollApprovedV2({
   requestId:request.requestId,signatureBase64url:'invalid',
   authenticatedAccountId:ACCOUNT,nowSeconds:1790000000,db
  }),/approver unavailable/);
  assert.equal(writes,0);
 });
}
