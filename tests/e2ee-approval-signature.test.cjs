'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {canonicalApproval}=require('../security/enrollment-approval-payload.cjs');
const {verifyApprovalSignature}=require('../security/enrollment-approval-verify.cjs');
const id=n=>n.toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
const payload={userId:id(1),requestId:id(2),proposedDeviceId:id(3),
 approverDeviceId:id(4),challenge:id(5),encryptionKeyHash:'a'.repeat(64),
 signingKeyHash:'b'.repeat(64),issuedAt:1000,expiresAt:1600};
const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=pair.publicKey.export({format:'jwk'});
const sig=crypto.sign('sha256',Buffer.from(canonicalApproval(payload)),
 {key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
assert.equal(verifyApprovalSignature(payload,sig,jwk),true);
for(const field of ['userId','requestId','proposedDeviceId','approverDeviceId','challenge']){
 assert.equal(verifyApprovalSignature({...payload,[field]:id(9)},sig,jwk),false);
}
for(const field of ['encryptionKeyHash','signingKeyHash']){
 assert.equal(verifyApprovalSignature({...payload,[field]:'c'.repeat(64)},sig,jwk),false);
}
assert.equal(verifyApprovalSignature({...payload,expiresAt:1599},sig,jwk),false);
assert.equal(verifyApprovalSignature(payload,'invalid',jwk),false);
const noncanonical=sig.slice(0,-1)+(sig.endsWith('A')?'B':'A');
assert.equal(verifyApprovalSignature(payload,noncanonical,jwk),false);
assert.equal(verifyApprovalSignature(payload,sig,null),false);
const other=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
assert.equal(verifyApprovalSignature(payload,sig,other.publicKey.export({format:'jwk'})),false);
assert.equal(verifyApprovalSignature(payload,sig,{...jwk,crv:'P-384'}),false);
console.log('E2EE P-256 approval signature primitive PASS (offline only)');
