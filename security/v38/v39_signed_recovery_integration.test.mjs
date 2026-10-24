import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {prepareRecoveryChallenge} from './v39_recovery_challenge_REFERENCE_NOT_DEPLOYED.mjs';
import {assessIndependentRecovery} from './v39_independent_recovery_gate_REFERENCE_NOT_DEPLOYED.mjs';
import {makeSignedRecoveryReceiptVerifier} from './v39_signed_authority_receipt_REFERENCE_NOT_DEPLOYED.mjs';
const ids={accountId:'11111111-1111-4111-8111-111111111111',candidateDeviceId:'22222222-2222-4222-8222-222222222222',requestId:'33333333-3333-4333-8333-333333333333',receiptId:'44444444-4444-4444-8444-444444444444'};
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const trustedIssuers=new Map([['independent-lab',publicKey.export({type:'spki',format:'pem'})]]);
const {challenge,serverRecord}=prepareRecoveryChallenge({...ids,now:1000,random:n=>Buffer.alloc(n,31)});
const receiptData={issuerId:'independent-lab',...ids,nonceSha256:serverRecord.nonceSha256,issuedAt:1000,expiresAt:301000};
function signed(fields=receiptData){
 const payload=JSON.stringify(['bharathlink.v39.independent-recovery-receipt.v1',fields.issuerId,fields.receiptId,fields.accountId,fields.candidateDeviceId,fields.requestId,fields.nonceSha256,fields.issuedAt,fields.expiresAt]);
 return {...fields,signature:sign(null,Buffer.from(payload),privateKey).toString('base64')};
}
const assess=(authorityReceipt,opts={})=>assessIndependentRecovery({
 challenge,serverRecord,authenticatedAccountId:ids.accountId,authorityReceipt,
 verifyAuthorityReceipt:makeSignedRecoveryReceiptVerifier({trustedIssuers,revokedReceiptIds:new Set(),now:()=>2000}),
 now:2000,...opts});
test('signed independent receipt passes signature verification but cannot enroll device',async()=>{
 const result=await assess(signed());
 assert.deepEqual(result,{allowed:false,reason:'ATOMIC_AUTHORITY_CONSUMPTION_REQUIRED'});
});
test('validly signed receipt for another request or device cannot cross-bind',async()=>{
 for(const changed of [
  {requestId:'55555555-5555-4555-8555-555555555555'},
  {candidateDeviceId:'66666666-6666-4666-8666-666666666666'},
  {accountId:'77777777-7777-4777-8777-777777777777'},
  {nonceSha256:'f'.repeat(64)}
 ]){
  const result=await assess(signed({...receiptData,...changed}));
  assert.deepEqual(result,{allowed:false,reason:'INDEPENDENT_VERIFICATION_FAILED'});
 }
});
test('revoked issuer receipt cannot pass integrated recovery gate',async()=>{
 const result=await assess(signed(),{verifyAuthorityReceipt:makeSignedRecoveryReceiptVerifier({
  trustedIssuers,revokedReceiptIds:new Set([ids.receiptId]),now:()=>2000})});
 assert.deepEqual(result,{allowed:false,reason:'INDEPENDENT_VERIFICATION_FAILED'});
});
