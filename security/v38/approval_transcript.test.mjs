import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {verifyApproval} from './verify_approval.mjs';
const input={accountId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222223',candidateDeviceId:'33333333-3333-4333-8333-333333333333',approverDeviceId:'44444444-4444-4444-8444-444444444444',candidateKeySha256:'a'.repeat(64),nonceSha256:'b'.repeat(64),expiresAt:1790000000};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const publicKeyJwk=publicKey.export({format:'jwk'});
const payload=approvalTranscript(input);
const signatureBase64url=sign('sha256',Buffer.from(payload),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
assert.equal(verifyApproval({publicKeyJwk,payload,signatureBase64url}),true);
for(const field of ['requestId','candidateDeviceId','approverDeviceId','candidateKeySha256','nonceSha256','expiresAt']){
 const changed={...input,[field]:field==='expiresAt'?input.expiresAt+1:field.endsWith('Sha256')?'c'.repeat(64):'55555555-5555-4555-8555-555555555555'};
 assert.equal(verifyApproval({publicKeyJwk,payload:approvalTranscript(changed),signatureBase64url}),false,field);
}
assert.throws(()=>approvalTranscript({...input,extra:'x'}));
assert.throws(()=>approvalTranscript({...input,approverDeviceId:input.candidateDeviceId}));
assert.throws(()=>approvalTranscript({...input,nonceSha256:'not-hex'}));
console.log('Versioned approval transcript: positive and negative binding tests PASS; integration disabled');
