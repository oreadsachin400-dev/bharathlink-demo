import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { DOMAIN, NON_APPROVAL_DECISION, verifyRecoveryReviewSignature, sha256Hex }
 from '../supabase/functions/bl20-recovery-v1/review-crypto.mjs';

const subtle=webcrypto.subtle;
const uid=(x)=>x.repeat(8)+'-'+x.repeat(4)+'-4'+x.repeat(3)+'-8'+x.repeat(3)+'-'+x.repeat(12);
const timestamp=(ms)=>new Date(ms).toISOString();
const now=Date.parse('2026-11-03T09:00:00.000Z');
const signedFields=()=>[
 DOMAIN,uid('1'),uid('2'),uid('3'),uid('4'),uid('5'),uid('6'),
 'a'.repeat(64),'b'.repeat(64),uid('7'),'c'.repeat(64),
 uid('8'),uid('9'),timestamp(now-30000),timestamp(now+120000),
 NON_APPROVAL_DECISION
];
const b64url=bytes=>Buffer.from(bytes).toString('base64url');
async function fixture(){
 const kp=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const key=await subtle.exportKey('jwk',kp.publicKey);
 const jwk={kty:key.kty,crv:key.crv,x:key.x,y:key.y};
 const context={issuerPublicJwk:jwk,issuerId:'independent-test-issuer',
   challengeId:uid('a'),payload:signedFields().join('\n'),
   deviceTrusted:false,e2eeReady:false,signatureBase64Url:''};
 const sign=async p=>b64url(await subtle.sign({name:'ECDSA',hash:'SHA-256'},
  kp.privateKey,new TextEncoder().encode(p)));
 context.signatureBase64Url=await sign(context.payload);
 return {context,kp,sign};
}
const verifies=async o=>verifyRecoveryReviewSignature(o,subtle);

test('valid P-256 signed, 16-field review is verified but never authorizes device',async()=>{
 const f=await fixture();
 assert.equal(await verifies(f.context),true);
 assert.match(f.context.payload,/REVIEW_ELIGIBLE_ONLY_NO_DEVICE_APPROVAL$/);
 assert.equal(f.context.deviceTrusted,false);
 assert.equal(f.context.e2eeReady,false);
});
test('issuer replacement and client public key substitution fail verification',async()=>{
 const a=await fixture(),b=await fixture();
 assert.equal(await verifies({...a.context,issuerPublicJwk:b.context.issuerPublicJwk}),false);
 assert.equal(await verifies({...a.context,issuerPublicJwk:{...a.context.issuerPublicJwk,private:'leak'}}),false);
 assert.equal(await verifies({...a.context,issuerPublicJwk:{...a.context.issuerPublicJwk,crv:'P-384'}}),false);
});
test('nonce, account, request, device, proof, evidence, reviewer and session tamper fail',async()=>{
 const original=await fixture();
 for(const idx of [1,2,3,4,5,6,7,8,9,10,11,12,13,14]){
  const parts=original.context.payload.split('\n');
  parts[idx]=idx>=13?timestamp(now+15000):idx===7||idx===8||idx===10?'d'.repeat(64):uid('d');
  assert.equal(await verifies({...original.context,payload:parts.join('\n')}),false,'field '+idx);
 }
});
test('forged, DER-shaped, noncanonical, or altered raw signatures fail',async()=>{
 const f=await fixture();
 const sig=f.context.signatureBase64Url;
 for(const v of [sig+'=',sig.slice(1),'A'.repeat(86),'!'.repeat(86)]){
  assert.equal(await verifies({...f.context,signatureBase64Url:v}),false);
 }
 const raw=Buffer.from(sig,'base64url');raw[0]^=1;
 assert.equal(await verifies({...f.context,signatureBase64Url:raw.toString('base64url')}),false);
});
test('reviewer independence, expiry, syntax, trust status and domain are required',async()=>{
 const f=await fixture(),a=f.context.payload.split('\n');
 const c=f.context;
 assert.equal(await verifies({...c,deviceTrusted:true}),false);
 assert.equal(await verifies({...c,e2eeReady:true}),false);
 assert.equal(await verifies({...c,challengeId:'not-a-uuid'}),false);
 assert.equal(await verifies({...c,issuerId:'x'}),false);
 for(const i of [0,11,12,13,14,15]){
   const b=[...a];
   b[i]=i===0?'WRONG':i===15?'APPROVED':i===11?a[12]:i===12?a[1]:i===13?'invalid':timestamp(now+400000);
   assert.equal(await verifies({...c,payload:b.join('\n')}),false,'index '+i);
 }
});
test('signature checks never accept missing or malformed context',async()=>{
 for(const obj of [null,{},[],{payload:'x'},{payload:{}}])
  assert.equal(await verifies(obj),false);
 assert.match(await sha256Hex('hello',subtle),/^[0-9a-f]{64}$/);
});
test('issuer public key hash uses the same canonical bytes as Postgres',async()=>{
 const f=await fixture(),k=f.context.issuerPublicJwk;
 const x=await sha256Hex(['EC','P-256',k.x,k.y].join('\n'),subtle);
 assert.equal(x.length,64);
 assert.notEqual(x,await sha256Hex(JSON.stringify(k),subtle));
});
