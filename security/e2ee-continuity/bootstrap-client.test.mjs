import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {
 b64url, fromB64url, p256Fingerprint, makeContext, claimPayload, derivedProofKey,
 rawSignature, sha256b64, utf8
} from './bootstrap-crypto.mjs';
import {proveExistingDevice} from './bootstrap-client.mjs';
const crypto=webcrypto, subtle=crypto.subtle;
const userId='11111111-1111-4111-8111-111111111111';
const deviceId='22222222-2222-4222-8222-222222222222';
const challengeId='33333333-3333-4333-8333-333333333333';
const orig=()=>subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
const signer=()=>subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
const bytes=v=>new Uint8Array(v);
async function fixture(){
 const original=await orig(), signing=await signer(), ephemeral=await orig();
 const originalPublicJwk=await subtle.exportKey('jwk',original.publicKey);
 const signingPublicJwk=await subtle.exportKey('jwk',signing.publicKey);
 const ephemeralPublicJwk=await subtle.exportKey('jwk',ephemeral.publicKey);
 const expiresAt=Date.now()+65_000;
 const challenge={userId,deviceId,challengeId,expiresAt,
  ecdhKeyHash:await p256Fingerprint(originalPublicJwk,subtle),
  signingKeyHash:await p256Fingerprint(signingPublicJwk,subtle),
  ephemeralPublicJwk};
 const context=makeContext(challenge);
 const key=await derivedProofKey(ephemeral.privateKey,originalPublicJwk,context,subtle);
 const secret=crypto.getRandomValues(new Uint8Array(32));
 const iv=crypto.getRandomValues(new Uint8Array(12));
 challenge.iv=b64url(iv);
 challenge.sealedSecret=b64url(bytes(await subtle.encrypt({name:'AES-GCM',iv,
   additionalData:utf8.encode(context)},key,secret)));
 return {
  original,signing,challenge,originalPublicJwk,signingPublicJwk,secret,context,
  params:{authUserId:userId,deviceId,originalPrivateKey:original.privateKey,
   originalPublicJwk,newSigningPrivateKey:signing.privateKey,
   newSigningPublicJwk:signingPublicJwk,challenge,confirmedByUser:true,
   subtle,now:()=>expiresAt-10000}
 };
}
test('real P-256 ECDH+HKDF+AES-GCM possession and ECDSA proof valid',async()=>{
 const f=await fixture();
 const result=await proveExistingDevice(f.params);
 assert.equal(result.challengeId,challengeId);
 assert.deepEqual(fromB64url(result.proofBase64Url),f.secret);
 const signingPub=await subtle.importKey('jwk',f.signingPublicJwk,
   {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const digest=await sha256b64(f.secret,subtle);
 assert.equal(await subtle.verify({name:'ECDSA',hash:'SHA-256'},signingPub,
   rawSignature(result.signatureBase64Url),
   utf8.encode(claimPayload(f.context,digest))),true);
});
test('no device-holder consent rejects before crypto',async()=>{
 const f=await fixture();
 await assert.rejects(proveExistingDevice({...f.params,confirmedByUser:false}),/confirmation required/);
});
test('wrong original key cannot decrypt server challenge',async()=>{
 const f=await fixture(),other=await orig();
 await assert.rejects(proveExistingDevice({...f.params,originalPrivateKey:other.privateKey}));
});
test('tampered ciphertext fails authentication',async()=>{
 const f=await fixture(),ct=fromB64url(f.challenge.sealedSecret);
 ct[7]^=1;
 await assert.rejects(proveExistingDevice({...f.params,challenge:{...f.challenge,sealedSecret:b64url(ct)}}));
});
test('tampered IV fails authentication',async()=>{
 const f=await fixture(),iv=fromB64url(f.challenge.iv);iv[0]^=1;
 await assert.rejects(proveExistingDevice({...f.params,challenge:{...f.challenge,iv:b64url(iv)}}));
});
test('changed account rejects before decryption',async()=>{
 const f=await fixture();
 await assert.rejects(proveExistingDevice({...f.params,authUserId:'44444444-4444-4444-8444-444444444444'}),/context mismatch/);
});
test('expired challenge rejects',async()=>{
 const f=await fixture();
 await assert.rejects(proveExistingDevice({...f.params,now:()=>f.challenge.expiresAt}),/expired/);
});
test('challenge cannot swap signing identity',async()=>{
 const f=await fixture(),other=await signer();
 const foreign=await subtle.exportKey('jwk',other.publicKey);
 await assert.rejects(proveExistingDevice({...f.params,newSigningPublicJwk:foreign}),/Pinned key mismatch/);
});
test('challenge cannot swap original public identity',async()=>{
 const f=await fixture(),other=await orig();
 const foreign=await subtle.exportKey('jwk',other.publicKey);
 await assert.rejects(proveExistingDevice({...f.params,originalPublicJwk:foreign}),/Pinned key mismatch/);
});
test('extractable original device key is rejected',async()=>{
 const f=await fixture(),other=await subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
 await assert.rejects(proveExistingDevice({...f.params,originalPrivateKey:other.privateKey}),/non-extractable/);
});
test('extractable signing key is rejected',async()=>{
 const f=await fixture(),other=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 await assert.rejects(proveExistingDevice({...f.params,newSigningPrivateKey:other.privateKey}),/Non-extractable signing/);
});
test('a wrong signing keypair cannot authenticate the claimed public key',async()=>{
 const f=await fixture(),other=await signer();
 await assert.rejects(proveExistingDevice({...f.params,newSigningPrivateKey:other.privateKey}),/Signing identity mismatch/);
});
test('noncanonical base64url is rejected',()=>{
 assert.throws(()=>fromB64url('Zg='),/base64url/);
 assert.throws(()=>fromB64url('Zh'),/Noncanonical/);
});
test('fake JWK with private d is rejected',async()=>{
 const f=await fixture();
 await assert.rejects(proveExistingDevice({...f.params,newSigningPublicJwk:{...f.signingPublicJwk,d:'fake'}}),/Invalid public P-256/);
});
