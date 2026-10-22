import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {candidateKeyDigest} from './candidate_key_digest.mjs';
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';
const now=1790000000;
const signingPublicKey=Buffer.alloc(32,1).toString('base64url');
const curve25519PublicKey=Buffer.alloc(32,2).toString('base64url');
const request={accountId:'11111111-1111-4111-8111-111111111111',
 requestId:'22222222-2222-4222-8222-222222222223',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 approverDeviceId:'44444444-4444-4444-8444-444444444444',
 candidateKeySha256:candidateKeyDigest({signingPublicKey,curve25519PublicKey}),
 nonceSha256:'a'.repeat(64),expiresAt:now+120};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(request)),
 {key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const anchor={accountId:request.accountId,deviceId:request.approverDeviceId,
 verified:true,revoked:false,publicKeyJwk:publicKey.export({format:'jwk'})};
function adapter({badKey=false,revoked=false,failConsume=false,wrongAnchorAccount=false,wrongAnchorDevice=false,wrongRequestAccount=false,wrongRequestDevice=false,notPending=false,failInsert=false}={}){
 const state={inserted:false,committed:false};
 return {state,db:{async transaction(fn){
   const tx={async lockPendingRequest(){return {...request,accountId:wrongRequestAccount?'99999999-9999-4999-8999-999999999999':request.accountId,candidateDeviceId:wrongRequestDevice?'99999999-9999-4999-8999-999999999998':request.candidateDeviceId,state:notPending?'approved':'pending',
      signingPublicKey,curve25519PublicKey:badKey?Buffer.alloc(32,3).toString('base64url'):curve25519PublicKey};},
     async lockTrustedAnchor(){return {...anchor,accountId:wrongAnchorAccount?'99999999-9999-4999-8999-999999999999':anchor.accountId,deviceId:wrongAnchorDevice?'99999999-9999-4999-8999-999999999998':anchor.deviceId,revoked};},
     async insertV2Device(v){assert.equal(v.protocolVersion,2);state.inserted=true;if(failInsert)throw new Error('insert failed');},
     async consumeRequest(){return !failConsume;}};
   try {const result=await fn(tx);state.committed=true;return result;}
   catch(e){state.inserted=false;throw e;}
 }}};
}
const args={requestId:request.requestId,authenticatedAccountId:request.accountId,
 signatureBase64url,nowSeconds:now};
const ok=adapter();assert.equal((await enrollApprovedV2({...args,db:ok.db})).deviceId,request.candidateDeviceId);
assert.equal(ok.state.committed,true);
for(const options of [{badKey:true},{revoked:true},{failConsume:true},{wrongAnchorAccount:true},{wrongAnchorDevice:true},{wrongRequestAccount:true},{wrongRequestDevice:true},{notPending:true},{failInsert:true}]){
 const x=adapter(options);
 await assert.rejects(enrollApprovedV2({...args,db:x.db}));
 assert.equal(x.state.committed,false);
}
await assert.rejects(enrollApprovedV2({...args,db:adapter().db,authenticatedAccountId:'99999999-9999-4999-8999-999999999999'}));
await assert.rejects(enrollApprovedV2({...args,db:adapter().db,signatureBase64url:'bad'}));
await assert.rejects(enrollApprovedV2({...args,db:adapter().db,nowSeconds:request.expiresAt}));
// Fail closed on absent transaction or missing row-lock primitives.
await assert.rejects(enrollApprovedV2({...args,db:{}}));
await assert.rejects(enrollApprovedV2({...args,db:{transaction:async fn=>fn({})}}));
console.log('PASS: isolated transaction coordinator positive and negative paths');
