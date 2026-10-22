import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {prepareVerifiedEnrollment} from './prepare_verified_enrollment.mjs';
const now=1790000000;
const request={accountId:'11111111-1111-4111-8111-111111111111',
 requestId:'22222222-2222-4222-8222-222222222223',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 approverDeviceId:'44444444-4444-4444-8444-444444444444',
 candidateKeySha256:'a'.repeat(64),nonceSha256:'b'.repeat(64),expiresAt:now+120};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(request)),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const anchor={accountId:request.accountId,deviceId:request.approverDeviceId,verified:true,revoked:false,publicKeyJwk:publicKey.export({format:'jwk'})};
const repository={async readRequest(id){return id===request.requestId?{...request,state:'pending'}:null;},
 async readTrustedAnchor(account,device){return account===request.accountId&&device===request.approverDeviceId?anchor:null;}};
const args={requestId:request.requestId,signatureBase64url,repository,nowSeconds:now};
const result=await prepareVerifiedEnrollment(args);
assert.equal(result.candidateDeviceId,request.candidateDeviceId);
assert.equal(Object.isFrozen(result),true);
await assert.rejects(prepareVerifiedEnrollment({...args,signatureBase64url:'invalid'}));
await assert.rejects(prepareVerifiedEnrollment({...args,requestId:'00000000-0000-4000-8000-000000000000'}));
await assert.rejects(prepareVerifiedEnrollment({...args,repository:{...repository,readRequest:async()=>({...request,state:'approved'})}}));
await assert.rejects(prepareVerifiedEnrollment({...args,repository:{...repository,readTrustedAnchor:async()=>({...anchor,revoked:true})}}));
await assert.rejects(prepareVerifiedEnrollment({...args,nowSeconds:request.expiresAt}));
await assert.rejects(prepareVerifiedEnrollment({...args,repository:{...repository,readRequest:async()=>({...request,nonceSha256:'c'.repeat(64),state:'pending'})}}));
console.log('PASS: reference-only enrollment coordinator rejects invalid authorization');
