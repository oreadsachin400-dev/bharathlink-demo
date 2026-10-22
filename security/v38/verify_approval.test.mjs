import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyApproval } from './verify_approval.mjs';

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const payload = 'BL-V38-APPROVAL\\naccount=11111111-1111-4111-8111-111111111111\\nrequest=22222222-2222-4222-8222-222222222223';
const signatureBase64url = sign('sha256', Buffer.from(payload), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
const check = (overrides={}) => verifyApproval({ publicKeyJwk:jwk, payload, signatureBase64url, ...overrides });
assert.equal(check(), true);
assert.equal(check({payload:payload+'x'}), false);
assert.equal(check({signatureBase64url:signatureBase64url.slice(0,-2)}), false);
assert.equal(check({signatureBase64url:signatureBase64url+'='}), false);
assert.equal(check({signatureBase64url:signatureBase64url+'!'}), false);
assert.equal(check({signatureBase64url:signatureBase64url.slice(0,-1)}), false);
assert.equal(check({publicKeyJwk:{...jwk,crv:'P-384'}}), false);
const other = generateKeyPairSync('ec', { namedCurve:'prime256v1' }).publicKey.export({format:'jwk'});
assert.equal(check({publicKeyJwk:other}), false);
console.log('P-256 offline verifier: 8/8 PASS (reference only; approval remains disabled)');
