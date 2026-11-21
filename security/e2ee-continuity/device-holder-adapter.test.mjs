import test from 'node:test';
import assert from 'node:assert/strict';
import {createDeviceHolderAdapter} from './device-holder-adapter.mjs';
const uid='11111111-1111-4111-8111-111111111111';
const did='22222222-2222-4222-8222-222222222222';
const cid='33333333-3333-4333-8333-333333333333';
const privateKey={type:'private',extractable:false,algorithm:{name:'ECDH',namedCurve:'P-256'}};
const pub={kty:'EC',crv:'P-256',x:'x',y:'y'};
const validStatus={statusOnly:true,releaseState:'SECURITY_HOLD',deviceApprovalEnabled:false,activeDeviceCount:2,verifiedSigningDeviceCount:0,pendingEnrollmentCount:0};
const base=()=>({
 currentUser:async()=>({id:uid}),
 readLocalDevice:async()=>({userId:uid,deviceId:did,privateKey,publicJwk:pub}),
 isActiveDevice:async()=>true,
 getSigningKey:async()=>({privateKey:{},publicJwk:pub}),
 proveExistingDevice:async()=>({challengeId:cid,proofBase64Url:'x',signatureBase64Url:'y'}),
 getTrustStatus:async()=>validStatus,
 beginChallenge:async()=>({ok:true,trustGranted:false,challenge:{userId:uid,deviceId:did,challengeId:cid,expiresAt:Date.now()+60_000}}),
 completeChallenge:async()=>({ok:true,continuityProven:true,trustGranted:false,deviceId:did,challengeId:cid,status:'continuity_proven_not_trusted'}),
 continuityReleaseEnabled:true
});
test('security hold disallows all network or signing calls',async()=>{
 let count=0;const d=base();d.currentUser=async()=>{count++};d.continuityReleaseEnabled=false;
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/SECURITY_HOLD/);assert.equal(count,0);
});
test('explicit approval required before reading account',async()=>{
 let count=0;const d=base();d.currentUser=async()=>{count++};
 await assert.rejects(createDeviceHolderAdapter(d).prove(),/Explicit/);assert.equal(count,0);
});
test('status is account scoped, no trust claim',async()=>{
 const r=await createDeviceHolderAdapter(base()).status();assert.equal(r.activeDeviceCount,2);assert.equal(r.trustGranted,false);
});
test('unknown status rejects',async()=>{
 const d=base();d.getTrustStatus=async()=>({...validStatus,releaseState:'RELEASED'});
 await assert.rejects(createDeviceHolderAdapter(d).status(),/Unrecognized/);
});
test('successful continuity is never promotion',async()=>{
 const r=await createDeviceHolderAdapter(base()).prove({confirmedByUser:true});
 assert.deepEqual(r,{continuityProven:true,trustGranted:false,status:'continuity_proven_not_trusted'});
});
test('local device missing blocks signing',async()=>{
 let touched=false;const d=base();d.readLocalDevice=async()=>null;
 d.getSigningKey=async()=>{touched=true};
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/do not auto-register/);
 assert.equal(touched,false);
});
test('extractable original key rejected',async()=>{
 const d=base();d.readLocalDevice=async()=>({userId:uid,deviceId:did,privateKey:{...privateKey,extractable:true},publicJwk:pub});
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/non-extractable/);
});
test('revoked device blocks signer creation',async()=>{
 let touched=false;const d=base();d.isActiveDevice=async()=>false;
 d.getSigningKey=async()=>{touched=true};
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/not active/);assert.equal(touched,false);
});
test('cross-account challenge blocks proof',async()=>{
 let touched=false;const d=base();
 d.beginChallenge=async()=>({ok:true,trustGranted:false,
 challenge:{userId:'44444444-4444-4444-8444-444444444444',deviceId:did,challengeId:cid,expiresAt:Date.now()+100000}});
 d.proveExistingDevice=async()=>{touched=true};
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/cross-account/);
 assert.equal(touched,false);
});
test('unexpected trust-granting server response rejected',async()=>{
 const d=base();d.completeChallenge=async()=>({ok:true,continuityProven:true,trustGranted:true,deviceId:did,challengeId:cid,status:'trusted'});
 await assert.rejects(createDeviceHolderAdapter(d).prove({confirmedByUser:true}),/not accepted/);
});
test('double click cannot start simultaneous flows',async()=>{
 let release;const d=base();d.beginChallenge=()=>new Promise(r=>{release=r});
 const a=createDeviceHolderAdapter(d);
 const one=a.prove({confirmedByUser:true});await new Promise(r=>setImmediate(r));
 await assert.rejects(a.prove({confirmedByUser:true}),/already in progress/);
 release(await base().beginChallenge());await one;
});
