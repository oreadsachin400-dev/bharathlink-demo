// CI-only guard: do not confuse existing V2 device signing keys with P-256 approver keys.
// TEST legacy RPC accepts 32-byte signing keys; V39 approval verification uses P-256 JWK.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {verifyApproval} from './verify_approval.mjs';
test('raw 32-byte V2 signing key cannot be treated as trusted P-256 approval anchor',()=>{
 const legacySigningKey=Buffer.alloc(32,7).toString('base64');
 const payload='BHARATHLINK-DEVICE-APPROVAL-V1\\nexample';
 assert.equal(verifyApproval({publicKeyJwk:legacySigningKey,payload,signatureBase64url:'invalid'}),false);
});
test('P-256 approval signature validates only against matching trusted P-256 key',()=>{
 const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const other=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey;
 const payload='BHARATHLINK-DEVICE-APPROVAL-V1\\nexample';
 const signatureBase64url=sign('sha256',Buffer.from(payload),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
 assert.equal(verifyApproval({publicKeyJwk:publicKey.export({format:'jwk'}),payload,signatureBase64url}),true);
 assert.equal(verifyApproval({publicKeyJwk:other.export({format:'jwk'}),payload,signatureBase64url}),false);
});
