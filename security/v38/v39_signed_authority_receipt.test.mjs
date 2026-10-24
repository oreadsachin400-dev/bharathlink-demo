import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {makeSignedRecoveryReceiptVerifier} from './v39_signed_authority_receipt_REFERENCE_NOT_DEPLOYED.mjs';
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const pub=publicKey.export({type:'spki',format:'pem'});
const ids={accountId:'11111111-1111-4111-8111-111111111111',
 candidateDeviceId:'22222222-2222-4222-8222-222222222222',
 requestId:'33333333-3333-4333-8333-333333333333',
 receiptId:'44444444-4444-4444-8444-444444444444'};
const nonceSha256='a'.repeat(64);
const expected={...ids,nonceSha256,expiresAt:301000};
function signed(overrides={}) {
 const r={issuerId:'trusted-lab',...ids,nonceSha256,issuedAt:1000,expiresAt:201000,...overrides};
 const t=JSON.stringify(['bharathlink.v39.independent-recovery-receipt.v1',
  r.issuerId,r.receiptId,r.accountId,r.candidateDeviceId,r.requestId,r.nonceSha256,r.issuedAt,r.expiresAt]);
 return {...r,signature:sign(null,Buffer.from(t),privateKey).toString('base64')};
}
const verifier=(options={})=>makeSignedRecoveryReceiptVerifier({
 trustedIssuers:new Map([['trusted-lab',pub]]),revokedReceiptIds:new Set(),now:()=>2000,...options});
test('pinned Ed25519 issuer verifies bound recovery receipt',async()=>{
 assert.equal(await verifier()(signed(),expected),true);
});
test('untrusted, revoked, tampered and expired receipts fail closed',async()=>{
 const valid=signed();
 const cases=[
  [verifier(),{...valid,signature:'A'.repeat(88)},expected],
  [verifier(),{...valid,accountId:'55555555-5555-4555-8555-555555555555'},expected],
  [verifier(),signed({issuerId:'untrusted'}),expected],
  [verifier({revokedReceiptIds:new Set([ids.receiptId])}),valid,expected],
  [verifier({now:()=>201000}),valid,expected],
  [verifier(),signed({expiresAt:401000}),expected],
  [verifier(),valid,{...expected,nonceSha256:'b'.repeat(64)}],
  [verifier(),valid,{...expected,requestId:'66666666-6666-4666-8666-666666666666'}],
 ];
 for(const [verify,receipt,context] of cases) assert.equal(await verify(receipt,context),false);
});
test('missing trusted server config rejects verifier construction',()=>{
 assert.throws(()=>makeSignedRecoveryReceiptVerifier({}));
});

test('verification uses a single trusted clock reading and rejects invalid clocks',async()=>{
 let reads=0;
 const check=verifier({now:()=>{reads++;return reads===1?2000:500000;}});
 assert.equal(await check(signed(),expected),true);
 assert.equal(reads,1);
 for(const value of [NaN,Infinity,-1,1.5]){
  const reject=verifier({now:()=>value});
  assert.equal(await reject(signed(),expected),false);
 }
});
