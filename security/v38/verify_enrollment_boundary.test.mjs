import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {verifyEnrollmentApproval} from './verify_enrollment_boundary.mjs';
const now=1790000000;
const request={
 accountId:'11111111-1111-4111-8111-111111111111',
 requestId:'22222222-2222-4222-8222-222222222223',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 approverDeviceId:'44444444-4444-4444-8444-444444444444',
 candidateKeySha256:'a'.repeat(64),nonceSha256:'b'.repeat(64),expiresAt:now+120
};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const trustedAnchor={accountId:request.accountId,deviceId:request.approverDeviceId,publicKeyJwk:publicKey.export({format:'jwk'}),verified:true,revoked:false};
const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(request)),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const base={request,storedRequest:{...request,state:'pending'},trustedAnchor,signatureBase64url,nowSeconds:now};
const check=(change={})=>verifyEnrollmentApproval({...base,...change});
assert.equal(check(),true);
assert.equal(check({storedRequest:{...request}}),false);
assert.equal(check({storedRequest:{...base.storedRequest,state:null}}),false);
assert.equal(check({storedRequest:{...base.storedRequest,state:'approved'}}),false);
assert.equal(check({storedRequest:{...base.storedRequest,nonceSha256:'c'.repeat(64)}}),false);
assert.equal(check({request:{...request,candidateKeySha256:'c'.repeat(64)}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,revoked:true}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,revoked:undefined}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,revoked:null}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,revoked:'false'}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,verified:false}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,accountId:'55555555-5555-4555-8555-555555555555'}}),false);
assert.equal(check({trustedAnchor:{...trustedAnchor,deviceId:request.candidateDeviceId}}),false);
assert.equal(check({signatureBase64url:'invalid'}),false);
assert.equal(check({nowSeconds:request.expiresAt}),false);
assert.equal(check({nowSeconds:now-600}),false);
console.log('Isolated enrollment signature boundary tests PASS; database finalizer remains disabled');
