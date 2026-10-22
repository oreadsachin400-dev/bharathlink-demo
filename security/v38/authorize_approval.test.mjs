import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {authorizeApproval} from './authorize_approval.mjs';
const now=1790000000;
const request={accountId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222223',candidateDeviceId:'33333333-3333-4333-8333-333333333333',approverDeviceId:'44444444-4444-4444-8444-444444444444',candidateKeySha256:'a'.repeat(64),nonceSha256:'b'.repeat(64),expiresAt:now+120};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const publicKeyJwk=publicKey.export({format:'jwk'});
const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(request)),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const good={accountId:request.accountId,publicKeyJwk,verified:true,revoked:false};
const trustedKeys=new Map([[request.approverDeviceId,good]]);
const run=(options={})=>authorizeApproval({request,signatureBase64url,trustedKeys,consumedRequests:new Set(),nowSeconds:now,...options});
assert.equal(run(),true);
assert.equal(run({trustedKeys:new Map()}),false);
assert.equal(run({trustedKeys:new Map([[request.approverDeviceId,{...good,verified:false}]])}),false);
assert.equal(run({trustedKeys:new Map([[request.approverDeviceId,{...good,revoked:true}]])}),false);
assert.equal(run({trustedKeys:new Map([[request.approverDeviceId,{...good,accountId:'55555555-5555-4555-8555-555555555555'}]])}),false);
assert.equal(run({nowSeconds:now+121}),false);
assert.equal(run({nowSeconds:now-1000}),false);
assert.equal(run({signatureBase64url:'bad'}),false);
const used=new Set();
assert.equal(run({consumedRequests:used}),true);
assert.equal(run({consumedRequests:used}),false);
// A signature for one request must not authorize a different account,
// request, candidate, approver, key fingerprint, nonce or expiry.
for (const [field, value] of [
  ['accountId','55555555-5555-4555-8555-555555555555'],
  ['requestId','66666666-6666-4666-8666-666666666666'],
  ['candidateDeviceId','77777777-7777-4777-8777-777777777777'],
  ['approverDeviceId','88888888-8888-4888-8888-888888888888'],
  ['candidateKeySha256','c'.repeat(64)],
  ['nonceSha256','d'.repeat(64)],
  ['expiresAt',now+119]
]) {
  assert.equal(run({request:{...request,[field]:value}}),false,
    'tampered field must be rejected: '+field);
}
assert.equal(run({request:{...request,candidateDeviceId:request.approverDeviceId}}),false);
assert.equal(run({request:{...request,unexpected:'value'}}),false);
assert.equal(run({request:{...request,expiresAt:now+601}}),false);
console.log('Trusted-key/expiry/replay offline checks PASS; production finalizer disabled');
