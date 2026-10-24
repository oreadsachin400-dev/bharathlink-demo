import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { verifyLegacyDeviceProof } from './v39_legacy_device_proof_REFERENCE_NOT_DEPLOYED.mjs';
const accountId='11111111-1111-4111-8111-111111111111',deviceId='22222222-2222-4222-8222-222222222222',requestId='33333333-3333-4333-8333-333333333333';
function fixture() {
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const raw=Buffer.from(publicKey.export({format:'jwk'}).x,'base64url');
 const anchor={accountId,deviceId,verified:true,revoked:false,algorithm:'Ed25519',signingPublicKey:raw.toString('base64')};
 const challenge={requestId,accountId,deviceId,nonce:randomBytes(32).toString('base64'),issuedAt:1000,expiresAt:2000,consumed:false};
 const transcript=JSON.stringify(['bharathlink.v39.legacy-device-proof.v1',requestId,accountId,deviceId,challenge.nonce,1000,2000,(awaitHash(raw))]);
 function awaitHash(b){return requireHash(b)}
 const response={requestId,accountId,deviceId,signature:sign(null,Buffer.from(transcript),privateKey).toString('base64')};
 return {anchor,challenge,response};
}
import { createHash } from 'node:crypto';
function requireHash(b){return createHash('sha256').update(b).digest('hex')}
test('valid Ed25519 possession proof',()=>{const f=fixture();assert.equal(verifyLegacyDeviceProof({...f,now:1500}).verified,true)});
for (const [name,mutate] of [
 ['cross account',f=>{f.response.accountId='44444444-4444-4444-8444-444444444444'}],
 ['revoked',f=>{f.anchor.revoked=true}],
 ['unverified',f=>{f.anchor.verified=false}],
 ['expired',f=>{}],
 ['replayed',f=>{f.challenge.consumed=true}],
 ['nonce tamper',f=>{f.challenge.nonce=randomBytes(32).toString('base64')}],
 ['wrong algorithm',f=>{f.anchor.algorithm='P-256'}],
 ['signature tamper',f=>{f.response.signature=randomBytes(64).toString('base64')}]
]) test(name,()=>{const f=fixture();mutate(f);assert.throws(()=>verifyLegacyDeviceProof({...f,now:name==='expired'?2000:1500}))});

test('missing revocation state is denied',()=>{const f=fixture();delete f.anchor.revoked;assert.throws(()=>verifyLegacyDeviceProof({...f,now:1500}))});
test('missing issue timestamp is denied',()=>{const f=fixture();delete f.challenge.issuedAt;assert.throws(()=>verifyLegacyDeviceProof({...f,now:1500}))});
test('non-integer issue timestamp is denied',()=>{const f=fixture();f.challenge.issuedAt='1000';assert.throws(()=>verifyLegacyDeviceProof({...f,now:1500}))});
test('reversed challenge time range is denied',()=>{const f=fixture();f.challenge.issuedAt=2000;assert.throws(()=>verifyLegacyDeviceProof({...f,now:1500}))});
test('invalid current time is denied',()=>{const f=fixture();assert.throws(()=>verifyLegacyDeviceProof({...f,now:NaN}))});
